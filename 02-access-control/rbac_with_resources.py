from prettytable import PrettyTable

ROLES = ["admin", "manager", "user"]

PERMISSIONS = {
    "admin": ["create", "read", "update", "delete"],
    "manager": ["create", "read"],
    "user": ["read"],
}


def check_permission(role, action):
    if role in PERMISSIONS:
        if action in PERMISSIONS[role]:
            return True
    return False


def authorization_check(permission):
    def authorization_decorator(function):
        def wrapper(*args, **kwargs):
            user_name = current_user.get("name")
            user_role = current_user.get("role")

            if check_permission(user_role, permission):
                return function(*args, **kwargs)
            else:
                return f"{user_name.upper()} not authorized for {permission.upper()}"

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

    current_user = {"name": "John Doe", "role": "user"}
    status = create_file()
    print(status)

    current_user = {"name": "Jean Doe", "role": "manager"}
    status = create_file()
    print(status)

    current_user = {"name": "Jean Doe", "role": "manager"}
    status = update_file()
    print(status)

    current_user = {"name": "Ivana Ivic", "role": "admin"}
    status = update_file()
    print(status)
