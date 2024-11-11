import re

import argon2
from argon2.exceptions import VerifyMismatchError
from sqlalchemy import select

from odp.config import config
from odp.const import ODPSystemRole, SAEON_EMAIL_DOMAINS
from odp.const.db import IdentityCommand
from odp.db import Session
from odp.db.models import Client, IdentityAudit, User, UserRole
from odp.lib import exceptions as x
from sadco.const import SADCORole

ph = argon2.PasswordHasher()


def get_user_by_email(email: str) -> User | None:
    return Session.execute(
        select(User).where(User.email == email)
    ).scalar_one_or_none()


def validate_user_login(
        client_id: str,
        email: str,
        password: str,
) -> str:
    """
    Validate the credentials supplied by a user via the login form, returning the user id
    on success. An ``ODPIdentityError`` is raised if the login cannot be permitted for any reason.

    :param client_id: the app from which login was initiated
    :param email: the input email address
    :param password: the input plain-text password
    :return: the user id

    :raises ODPUserNotFound: if the email address is not associated with any user account
    :raises ODPAccountLocked: if the user account has been temporarily locked
    :raises ODPIncorrectPassword: if the password is incorrect
    :raises ODPAccountDisabled: if the user account has been deactivated
    :raises ODPEmailNotVerified: if the email address has not yet been verified
    """
    try:
        if not Session.get(Client, client_id):
            raise x.ODPClientNotFound

        if not (user := get_user_by_email(email)):
            raise x.ODPUserNotFound

        # no password => either it's a non-human user (e.g. harvester),
        # or the user must be externally authenticated (e.g. via Google)
        if not user.password:
            raise x.ODPNoPassword

        # first check whether the account is currently locked and should still be locked, unlocking it if necessary
        if is_account_locked(user.id):
            raise x.ODPAccountLocked

        # check the password before checking further account properties, to minimize the amount of knowledge
        # a potential attacker can gain about an account
        try:
            ph.verify(user.password, password)

            # if argon2_cffi's password hashing defaults have changed, we rehash the user's password
            if ph.check_needs_rehash(user.password):
                user.password = ph.hash(password)
                user.save()

        except VerifyMismatchError:
            if lock_account(user.id):
                raise x.ODPAccountLocked
            raise x.ODPIncorrectPassword

        if not user.active:
            raise x.ODPAccountDisabled

        if not user.verified:
            raise x.ODPEmailNotVerified

        assign_sadco_role(client_id, user.id)

        _create_audit_record(client_id, IdentityCommand.login, True, user_id=user.id)
        return user.id

    except x.ODPIdentityError as e:
        _create_audit_record(client_id, IdentityCommand.login, False, e, email=email)
        raise


def validate_auto_login(
        client_id: str,
        user_id: str,
) -> None:
    """
    Validate a login request for which Hydra has indicated that the user is already authenticated,
    returning the user object on success. An ``ODPIdentityError`` is raised if the login cannot be
    permitted for any reason.

    :param client_id: the app from which login was initiated
    :param user_id: the user id

    :raises ODPUserNotFound: if the user account associated with this id has been deleted
    :raises ODPAccountLocked: if the user account has been temporarily locked
    :raises ODPAccountDisabled: if the user account has been deactivated
    :raises ODPEmailNotVerified: if the user changed their email address since their last login,
        but have not yet verified it
    """
    try:
        if not Session.get(Client, client_id):
            raise x.ODPClientNotFound

        if not (user := Session.get(User, user_id)):
            raise x.ODPUserNotFound

        if is_account_locked(user_id):
            raise x.ODPAccountLocked

        if not user.active:
            raise x.ODPAccountDisabled

        if not user.verified:
            raise x.ODPEmailNotVerified

        assign_sadco_role(client_id, user.id)

        _create_audit_record(client_id, IdentityCommand.login, True, user_id=user_id)

    except x.ODPIdentityError as e:
        _create_audit_record(client_id, IdentityCommand.login, False, e, user_id=user_id)
        raise


def is_account_locked(user_id):
    # todo...
    return False


def lock_account(user_id):
    # todo...
    return False


def validate_forgot_password(
        client_id: str,
        email: str,
) -> str:
    """
    Validate that a forgotten password request is for a valid email address.

    :param client_id: the app from which login was initiated
    :param email: the input email address
    :return: the user id

    :raises ODPUserNotFound: if there is no user account for the given email address
    :raises ODPAccountLocked: if the user account has been temporarily locked
    :raises ODPAccountDisabled: if the user account has been deactivated
    """
    try:
        if not Session.get(Client, client_id):
            raise x.ODPClientNotFound

        if not (user := get_user_by_email(email)):
            raise x.ODPUserNotFound

        if is_account_locked(user.id):
            raise x.ODPAccountLocked

        if not user.active:
            raise x.ODPAccountDisabled

        # we'll create the completion audit record in validate_password_reset
        return user.id

    except x.ODPIdentityError as e:
        _create_audit_record(client_id, IdentityCommand.change_password, False, e, email=email)
        raise


def validate_password_reset(
        client_id: str,
        email: str,
        password: str,
) -> str:
    """
    Validate a new password set by the user.

    :param client_id: the app from which login was initiated
    :param email: the user's email address
    :param password: the new password
    :return: the user id

    :raises ODPUserNotFound: if the email address is not associated with any user account
    :raises ODPPasswordComplexityError: if the password does not meet the minimum complexity requirements
    """
    try:
        if not Session.get(Client, client_id):
            raise x.ODPClientNotFound

        if not (user := get_user_by_email(email)):
            raise x.ODPUserNotFound

        if not check_password_complexity(email, password):
            raise x.ODPPasswordComplexityError

        _create_audit_record(client_id, IdentityCommand.change_password, True, email=email)
        return user.id

    except x.ODPIdentityError as e:
        _create_audit_record(client_id, IdentityCommand.change_password, False, e, email=email)
        raise


def validate_email_verification(
        client_id: str,
        email: str,
) -> str:
    """
    Validate an email verification.

    :param client_id: the app from which login was initiated
    :param email: the user's email address
    :return: the user id

    :raises ODPUserNotFound: if the email address is not associated with any user account
    """
    try:
        if not Session.get(Client, client_id):
            raise x.ODPClientNotFound

        if not (user := get_user_by_email(email)):
            raise x.ODPUserNotFound

        _create_audit_record(client_id, IdentityCommand.verify_email, True, email=email)
        return user.id

    except x.ODPIdentityError as e:
        _create_audit_record(client_id, IdentityCommand.verify_email, False, e, email=email)
        raise


def create_user_account(
        client_id: str,
        email: str,
        password: str = None,
        name: str = None,
) -> str:
    """
    Create a new user account with the specified credentials and
    assign a default role. Password may be omitted if the user is
    externally authenticated. An ``ODPIdentityError`` is raised if
    the account cannot be created for any reason.

    The password, if supplied, is hashed using the Argon2id algorithm.

    :param client_id: the app from which signup was initiated
    :param email: the input email address
    :param password: (optional) the input plain-text password
    :param name: (optional) the user's personal name
    :return: the new user id

    :raises ODPEmailInUse: if the email address is already associated with a user account
    :raises ODPPasswordComplexityError: if the password does not meet the minimum complexity requirements
    """
    try:
        if not Session.get(Client, client_id):
            raise x.ODPClientNotFound

        if get_user_by_email(email):
            raise x.ODPEmailInUse

        if password is not None and not check_password_complexity(email, password):
            raise x.ODPPasswordComplexityError

        user = User(
            email=email,
            password=ph.hash(password) if password else None,
            active=True,
            verified=False,
            name=name or '',
        )
        user.save()

        assign_sadco_role(client_id, user.id)

        assign_default_role(user.id)

        _create_audit_record(client_id, IdentityCommand.signup, True, email=email)
        return user.id

    except x.ODPIdentityError as e:
        _create_audit_record(client_id, IdentityCommand.signup, False, e, email=email)
        raise


def assign_default_role(user_id):
    """
    Assign the default SAEON staff role if the email domain belongs
    to SAEON, otherwise assign the default public user role.
    """
    user = Session.get(User, user_id)
    _, _, domain = user.email.partition('@')

    default_role = ODPSystemRole.SAEON_STAFF if domain in SAEON_EMAIL_DOMAINS else ODPSystemRole.DEFAULT

    if not Session.get(UserRole, (user_id, default_role)):
        user_role = UserRole(user_id=user_id, role_id=default_role)
        user_role.save()


def assign_sadco_role(client_id, user_id):
    """
    Assign the SADCO role if the user has come from the SADCO client and does not have the role already.
    """
    if client_id != config.ODP.IDENTITY.SADCO_CLIENT_ID:
        return

    if not Session.get(UserRole, (user_id, SADCORole.SADCO_USER)):
        user_role = UserRole(user_id=user_id, role_id=SADCORole.SADCO_USER)
        user_role.save()


def update_user_verified(user_id, verified):
    """
    Update the verified status of a user.

    :param user_id: the user id
    :param verified: True/False
    """
    user = Session.get(User, user_id)
    user.verified = verified
    user.save()


def update_user_password(user_id, password):
    """
    Update a user's password.

    :param user_id: the user id
    :param password: the input plain-text password
    """
    user = Session.get(User, user_id)
    user.password = ph.hash(password)
    user.save()


def check_password_complexity(email, password):
    """
    Check that a password meets the minimum complexity requirements,
    returning True if the requirements are satisfied, False otherwise.

    The rules are:
        - minimum length 10
        - at least one lowercase letter
        - at least one uppercase letter
        - at least one numeric character
        - at least one symbol character
        - a maximum of 3 consecutive characters from the email address

    :param email: the user's email address
    :param password: the input plain-text password
    :return: boolean
    """
    if len(password) < 10:
        return False
    if not re.search(r'[a-z]', password):
        return False
    if not re.search(r'[A-Z]', password):
        return False
    if not re.search(r'[0-9]', password):
        return False
    if not re.search(r'''[`~!@#$%^&*()\-=_+\[\]{}\\|;:'",.<>/?]''', password):
        return False
    for i in range(len(email) - 3):
        if email[i:(i + 4)] in password:
            return False

    return True


def password_complexity_description():
    return "The password must contain at least 10 characters, including 1 uppercase, " \
           "1 lowercase, 1 numeric, 1 symbol, and a maximum of 3 consecutive characters " \
           "from your email address."


def validate_google_login(
        client_id: str,
        email: str,
) -> str:
    """
    Validate a login completed via Google, returning the user id on success.
    An ``ODPIdentityError`` is raised if the login cannot be permitted for any reason.

    :param client_id: the app from which login was initiated
    :param email: the Google email address
    :return: the user id

    :raises ODPUserNotFound: if there is no user account for the given email address
    :raises ODPAccountLocked: if the user account has been temporarily locked
    :raises ODPAccountDisabled: if the user account has been deactivated
    :raises ODPEmailNotVerified: if the email address has not been verified
    """
    try:
        if not Session.get(Client, client_id):
            raise x.ODPClientNotFound

        if not (user := get_user_by_email(email)):
            raise x.ODPUserNotFound

        if is_account_locked(user.id):
            raise x.ODPAccountLocked

        if not user.active:
            raise x.ODPAccountDisabled

        assign_sadco_role(client_id, user.id)

        _create_audit_record(client_id, IdentityCommand.login, True, user_id=user.id)
        return user.id

    except x.ODPIdentityError as e:
        _create_audit_record(client_id, IdentityCommand.login, False, e, email=email)
        raise


def update_user_profile(user_id, **userinfo):
    """
    Update optional user profile info.

    Only update user attributes that are supplied in the dict.

    :param user_id: the user id
    :param userinfo: dict containing profile info
    """
    user = Session.get(User, user_id)
    for attr in 'name', 'picture':
        if attr in userinfo:
            setattr(user, attr, userinfo[attr])
    user.save()


def get_user_profile(user_id):
    """
    Return a dict of user profile info.
    """
    user = Session.get(User, user_id)
    info = {}
    for attr in 'name', 'picture':
        info[attr] = getattr(user, attr)
    return info


def get_user_profile_by_email(email):
    """
    Return a dict of user profile info.
    """
    user = get_user_by_email(email)
    if not user:
        raise x.ODPUserNotFound

    return get_user_profile(user.id)


def _create_audit_record(
        client_id: str,
        command: IdentityCommand,
        completed: bool,
        exc: x.ODPIdentityError = None,
        *,
        user_id: str = None,
        email: str = None,
):
    if user_id:
        user = Session.get(User, user_id)
        email = user.email if user else None
    elif email:
        user = get_user_by_email(email)
        user_id = user.id if user else None
    else:
        assert False

    IdentityAudit(
        client_id=client_id,
        command=command,
        completed=completed,
        error=exc.error_code if exc else None,
        _id=user_id,
        _email=email,
        _active=user.active if user else None,
        _roles=[role.id for role in user.roles] if user else None,
    ).save()
