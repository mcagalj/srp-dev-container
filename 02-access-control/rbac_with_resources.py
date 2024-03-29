from dataclasses import dataclass

from prettytable import PrettyTable

ROLES = ["admin", "manager", "user"]

PERMISSIONS = {
    "admin": ["create", "read", "update", "delete"],
    "manager": ["create", "read"],
    "user": ["read"],
}


@dataclass
class User:
    name: str
    role: str


def check_permission(role, action):
    return role in PERMISSIONS and action in PERMISSIONS[role]


def authorization_check(permission):
    def authorization_decorator(function):
        def wrapper(*args, **kwargs):
            user_name = current_user.name
            user_role = current_user.role

            if check_permission(user_role, permission):
                print(
                    f"\n{user_name.upper()} ({user_role}) "
                    f"authorized to {permission.upper()}"
                )
                return function(*args, **kwargs)
            else:
                print(
                    f"\n{user_name.upper()} ({user_role}) "
                    f"not authorized to {permission.upper()}"
                )
                return None

        return wrapper

    return authorization_decorator


@authorization_check(permission="create")
def create_file():
    return "File created"


@authorization_check(permission="read")
def read_file():
    return "File content"


@authorization_check(permission="update")
def update_file():
    return "File content updated"


@authorization_check(permission="delete")
def delete_file():
    return "File deleted"


if __name__ == "__main__":
    table = PrettyTable()
    table.field_names = ["Role", "Authorization", "Action"]
    table.align = "l"

    for action in ["create", "read", "update", "delete"]:
        for role in ROLES:
            table.add_row(
                [
                    role,
                    "CAN" if check_permission(role, action) else "CANNOT",
                    action,
                ]
            )

    print(table)

    current_user = User(name="John Doe", role="user")
    status = create_file()
    print(status)

    current_user = User(name="Jean Doe", role="manager")
    status = create_file()
    print(status)

    status = update_file()
    print(status)

    current_user = User(name="Ivana Ivic", role="admin")
    status = update_file()
    print(status)
