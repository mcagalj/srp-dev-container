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
