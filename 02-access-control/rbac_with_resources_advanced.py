import uuid

from prettytable import PrettyTable

ROLES = ["admin", "manager", "user"]

PERMISSIONS = {
    "admin": ["create", "read", "update", "delete"],
    "manager": ["create", "read"],
    "user": ["read"],
}


def check_permission(role, action):
    return role in PERMISSIONS and action in PERMISSIONS[role]


def authorization_check(permission):
    def authorization_decorator(function):
        def wrapper(*args, **kwargs):
            user_id = current_user.get("id")
            user_name = current_user.get("name")
            user_role = current_user.get("role")

            file = kwargs.get("file")

            if (
                file is not None
                and file.get("owner_id") == user_id
                or check_permission(user_role, permission)
            ):
                print(
                    f"\n{user_name.upper()} ({user_role}, {user_id}) "
                    f"authorized to {permission.upper()}"
                )
                return function(*args, **kwargs)
            else:
                print(
                    f"\n{user_name.upper()} ({user_role}, {user_id}) "
                    f"not authorized to {permission.upper()}"
                )
                return None

        return wrapper

    return authorization_decorator


def missing_file_check(function):
    def wrapper(*args, **kwargs):
        file = kwargs.get("file")
        if file is None:
            return "No such file"
        else:
            return function(*args, **kwargs)

    return wrapper


@authorization_check(permission="create")
def create_file(*, owner_id, filename):
    return {"id": uuid.uuid4(), "owner_id": owner_id, "name": filename}


@missing_file_check
@authorization_check(permission="read")
def read_file(*, file):
    return f"{file['name']}: content"


@missing_file_check
@authorization_check(permission="update")
def update_file(*, file):
    return f"{file['name']}: content updated"


@missing_file_check
@authorization_check(permission="delete")
def delete_file(*, file):
    return f"{file['name']}: deleted"


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

    # Current user is John Doe (manager)
    current_user = {"id": 1, "name": "John Doe", "role": "manager"}
    current_user_file = create_file(
        owner_id=current_user["id"], filename="SRP_lab_report"
    )
    print(f"Created file: {current_user_file}")

    current_user = {"id": 2, "name": "Ivana Ivic", "role": "user"}
    status = read_file(file=current_user_file)
    print(status)

    current_user = {"id": 4, "name": "Mate Matic", "role": "manager"}
    status = delete_file(file=current_user_file)
    print(status)

    current_user = {"id": 0, "name": "Jean Doe", "role": "admin"}
    status = delete_file(file=current_user_file)
    print(status)

    current_user = {"id": 1, "name": "John Doe", "role": "manager"}
    status = update_file(file=current_user_file)
    print(status)

    current_user = {"id": 1, "name": "John Doe", "role": "manager"}
    status = delete_file(file=current_user_file)
    print(status)
