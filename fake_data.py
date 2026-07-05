"""
fake_data.py — Dynamic Fake Data Generation Engine
Smart Web Honeypot | FYP01-CS-2530-0463

Generates realistic-looking fake data for deep honeypot engagement:
  - Fake user accounts
  - Fake database records (for SQLi attackers)
  - Fake file listings
  - Fake API responses
"""

import random
import json
from datetime import datetime, timedelta


class FakeDataGenerator:
    """Generate contextually-appropriate fake data for deception responses."""

    FIRST_NAMES = [
        "John", "Sarah", "Michael", "Jennifer", "David", "Emily", "Robert",
        "Lisa", "James", "Mary", "William", "Patricia", "Richard", "Linda"
    ]

    LAST_NAMES = [
        "Smith", "Johnson", "Williams", "Brown", "Jones", "Garcia", "Miller",
        "Davis", "Rodriguez", "Martinez", "Hernandez", "Lopez", "Gonzalez"
    ]

    DEPARTMENTS = [
        "Engineering", "Sales", "Marketing", "HR", "Finance",
        "Operations", "Support", "Product", "Legal", "Admin"
    ]

    DOMAINS = ["example.com", "company.net", "corp.org", "enterprise.io"]

    TITLES = [
        "Engineer", "Manager", "Developer", "Analyst", "Director",
        "Specialist", "Lead", "Coordinator", "Administrator", "Officer"
    ]

    DATABASES_SCHEMAS = {
        "users": {
            "columns": ["id", "username", "password_hash", "email", "phone", "role", "created_at"],
            "sample": [
                ["1", "admin", "5e884898da28047151d0e56f8dc62927", "admin@company.com", "555-0001", "admin", "2020-01-15"],
                ["2", "jsmith", "5f4dcc3b5aa765d61d8327deb882cf99", "j.smith@company.com", "555-0002", "user", "2020-02-20"],
                ["3", "mbrown", "6512bd43d9caa6e02c990b0a82652dca", "m.brown@company.com", "555-0003", "user", "2020-03-10"],
                ["4", "kdavis", "c20ad4d76fe97759aa27a0c99bff6710", "k.davis@company.com", "555-0004", "manager", "2020-04-05"],
                ["5", "rjones", "d41d8cd98f00b204e9800998ecf8427e", "r.jones@company.com", "555-0005", "user", "2020-05-12"],
            ]
        },
        "accounts": {
            "columns": ["account_id", "company_name", "account_manager", "balance", "status"],
            "sample": [
                ["ACC-001", "TechCorp Inc", "John Smith", "250000.00", "active"],
                ["ACC-002", "GlobalServices Ltd", "Sarah Johnson", "125000.00", "active"],
                ["ACC-003", "DataSystems Corp", "Michael Chen", "475000.00", "premium"],
                ["ACC-004", "CloudHost Solutions", "Emily Davis", "89000.00", "active"],
                ["ACC-005", "SecureNet Inc", "Robert Wilson", "340000.00", "active"],
            ]
        },
        "products": {
            "columns": ["product_id", "name", "price", "stock", "category"],
            "sample": [
                ["P001", "Software License - Enterprise", "99999.00", "100", "software"],
                ["P002", "Cloud Service - 1 Year", "45000.00", "500", "services"],
                ["P003", "Support Package - Premium", "25000.00", "200", "support"],
                ["P004", "Training Course - Advanced", "5000.00", "50", "training"],
                ["P005", "Consulting Hours - Senior", "500.00", "1000", "consulting"],
            ]
        }
    }

    FILE_STRUCTURES = {
        "/var/www": [
            "index.html", "config.php", "database.php", ".htaccess",
            "admin/", "uploads/", "includes/", "templates/",
            "wp-config.php", "wp-admin/", "wp-content/plugins/",
            ".env", ".git/", ".ssh/", "backup.sql.gz"
        ],
        "/home": [
            "user1/", "user2/", "admin/", "shared/",
            ".bash_history", ".ssh/", ".profile", ".bashrc"
        ],
        "/etc": [
            "passwd", "shadow", "hosts", "hostname",
            "apache2/", "mysql/", "nginx/", "ssh/",
            "ssl/", "cron.d/", "sudoers"
        ]
    }

    API_RESPONSES = {
        "user_profile": {
            "id": "12345",
            "username": "user@company.com",
            "email": "user@company.com",
            "created_at": "2020-01-15T10:30:00Z",
            "last_login": "2024-06-14T14:22:15Z",
            "role": "user",
            "permissions": ["read", "write", "profile"]
        },
        "auth_token": {
            "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
        },
        "company_data": {
            "company_id": "COMP-2024-001",
            "name": "Enterprise Corporation",
            "employees": 450,
            "revenue": "45M USD",
            "industry": "Technology",
            "founded": 2010,
            "headquarters": "San Francisco, CA"
        }
    }

    @staticmethod
    def generate_user():
        """Generate a fake user account."""
        first_name = random.choice(FakeDataGenerator.FIRST_NAMES)
        last_name = random.choice(FakeDataGenerator.LAST_NAMES)
        domain = random.choice(FakeDataGenerator.DOMAINS)
        username = f"{first_name.lower()}.{last_name.lower()}"
        email = f"{username}@{domain}"

        return {
            "id": random.randint(1000, 9999),
            "username": username,
            "email": email,
            "password_hash": "5e884898da28047151d0e56f8dc62927",
            "first_name": first_name,
            "last_name": last_name,
            "department": random.choice(FakeDataGenerator.DEPARTMENTS),
            "title": random.choice(FakeDataGenerator.TITLES),
            "phone": f"555-{random.randint(1000, 9999)}",
            "created_at": (datetime.now() - timedelta(days=random.randint(30, 1000))).isoformat(),
            "status": random.choice(["active", "inactive", "pending"])
        }

    @staticmethod
    def generate_users(count=5):
        """Generate multiple fake users."""
        return [FakeDataGenerator.generate_user() for _ in range(count)]

    @staticmethod
    def generate_fake_database_dump(table_name="users"):
        """
        Generate a fake database dump for SQLi attackers.
        Tables: users, accounts, products
        """
        if table_name not in FakeDataGenerator.DATABASES_SCHEMAS:
            table_name = "users"

        schema = FakeDataGenerator.DATABASES_SCHEMAS[table_name]

        # Build table header
        dump = f"\n{'='*60}\n"
        dump += f"Database Dump: {table_name}\n"
        dump += f"Generated: {datetime.now().isoformat()}\n"
        dump += f"{'='*60}\n\n"

        # Add schema
        dump += f"Columns: {', '.join(schema['columns'])}\n"
        dump += "-" * 60 + "\n"

        # Add sample rows
        for row in schema["sample"]:
            dump += " | ".join(row) + "\n"

        dump += "\n" + "=" * 60 + "\n"
        dump += f"Total Rows: {len(schema['sample'])}\n"
        dump += "=" * 60 + "\n"

        return dump

    @staticmethod
    def generate_file_listing(path="/var/www"):
        """Generate a fake directory listing."""
        if path not in FakeDataGenerator.FILE_STRUCTURES:
            path = "/var/www"

        files = FakeDataGenerator.FILE_STRUCTURES[path]
        listing = f"\nDirectory Listing: {path}\n"
        listing += "-" * 60 + "\n"
        listing += "Type       Permissions  Size    Modified              Name\n"
        listing += "-" * 60 + "\n"

        for file in files:
            is_dir = file.endswith("/")
            file_type = "dir" if is_dir else "file"
            perms = "drwxr-xr-x" if is_dir else "-rw-r--r--"
            size = "-" if is_dir else f"{random.randint(100, 50000)} B"
            modified = (datetime.now() - timedelta(days=random.randint(1, 365))).strftime("%Y-%m-%d %H:%M")

            listing += f"{file_type:10} {perms:12} {size:>7}  {modified:18}  {file}\n"

        listing += "-" * 60 + "\n"
        return listing

    @staticmethod
    def generate_session_token():
        """Generate a fake session/auth token."""
        import base64
        random_bytes = bytes([random.randint(0, 255) for _ in range(32)])
        token = base64.b64encode(random_bytes).decode().rstrip("=")
        return token

    @staticmethod
    def generate_cookie_values():
        """Generate fake cookie values."""
        return {
            "SESSIONID": FakeDataGenerator.generate_session_token(),
            "CSRF_TOKEN": FakeDataGenerator.generate_session_token(),
            "USER_ID": str(random.randint(1000, 9999)),
            "PREFERENCES": "lang=en&theme=light&notifications=true"
        }

    @staticmethod
    def generate_sql_error():
        """Generate realistic-looking SQL error message."""
        errors = [
            f"SQL Error [{random.randint(1000, 9999)}]: Syntax error near line {random.randint(1, 50)}",
            f"Database Error: Access Denied for user '{random.choice(['admin', 'root', 'db_user'])}' @ localhost",
            f"MySQL Error {random.randint(1000, 9999)}: Table '{random.choice(['users', 'accounts', 'data'])}' doesn't exist",
            f"SQLITE_CANTOPEN: unable to open database file",
            f"ORA-{random.randint(10000, 99999)}: invalid SQL statement"
        ]
        return random.choice(errors)

    @staticmethod
    def generate_api_response(response_type="user_profile"):
        """Generate a fake API response."""
        if response_type not in FakeDataGenerator.API_RESPONSES:
            response_type = "user_profile"

        response = FakeDataGenerator.API_RESPONSES[response_type].copy()

        # Add realistic metadata
        response["_meta"] = {
            "timestamp": datetime.now().isoformat(),
            "version": "1.2.3",
            "server": "nginx/1.18.0"
        }

        return response

    @staticmethod
    def generate_credentials():
        """Generate a pair of fake credentials."""
        user = FakeDataGenerator.generate_user()
        return {
            "username": user["username"],
            "password": random.choice([
                "Welcome123!", "Secure@2024", "Company#123",
                "MyPassword2024!", "SecurePass@123"
            ]),
            "email": user["email"],
            "token": FakeDataGenerator.generate_session_token()
        }

    @staticmethod
    def generate_access_log_entry():
        """Generate a fake access log entry."""
        methods = ["GET", "POST", "PUT", "DELETE", "PATCH"]
        paths = ["/api/users", "/admin", "/data", "/config", "/backup"]
        codes = [200, 201, 400, 401, 403, 404, 500]

        timestamp = datetime.now() - timedelta(seconds=random.randint(0, 3600))
        remote_ip = f"{random.randint(1, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 255)}"

        return (
            f"{remote_ip} - - [{timestamp.strftime('%d/%b/%Y %H:%M:%S')}] "
            f'"{random.choice(methods)} {random.choice(paths)} HTTP/1.1" '
            f"{random.choice(codes)} {random.randint(100, 5000)}"
        )


# Export convenience function
def get_fake_data(data_type="user"):
    """Get any type of fake data by name."""
    mapping = {
        "user": FakeDataGenerator.generate_user,
        "users": lambda: FakeDataGenerator.generate_users(5),
        "database": lambda: FakeDataGenerator.generate_fake_database_dump(),
        "files": lambda: FakeDataGenerator.generate_file_listing(),
        "credentials": FakeDataGenerator.generate_credentials,
        "token": FakeDataGenerator.generate_session_token,
        "cookies": FakeDataGenerator.generate_cookie_values,
        "api": lambda: FakeDataGenerator.generate_api_response(),
        "error": FakeDataGenerator.generate_sql_error,
        "log": FakeDataGenerator.generate_access_log_entry
    }

    if data_type in mapping:
        return mapping[data_type]()

    return FakeDataGenerator.generate_user()