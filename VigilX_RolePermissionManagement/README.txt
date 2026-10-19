VIGILX - ROLE & PERMISSION MANAGEMENT EDITION
==========================================================

This edition preserves password authentication and adds persistent role changes plus resource-specific READ/WRITE/DELETE permission rules.

New main menu options:
19. Change My Password
20. Admin: Unlock User Account
21. Admin: Change User Role
22. Admin: Role & Permission Management

Security features:
- Admin-only role changes among Admin, Employee and Guest; password/account data is preserved during a role change.
- Persistent custom permission rules for each username, resource ID and action (READ, WRITE, DELETE).
- Admin can grant, explicitly deny/revoke, list, or remove a custom rule to restore role-based defaults.
- Resource access requests now specify an action and are checked against custom rules first, then role/classification defaults.
- Role changes and permission changes are written to security_logs.txt.
- New users must create a password with at least 8 characters and confirm it.
- Passwords are stored as salted SHA-256 digests, not as plain-text passwords.
- Three incorrect password attempts lock the account.
- A logged-in Admin can unlock a locked account; the failed-attempt counter is reset.
- Users can change their own password after entering the current password.
- Failed login attempts, successful logins, password changes and account unlocks are logged.
- Account lock status, failed-attempt count, password salt and digest persist in users.txt.
- Older users.txt records with only ID, role and username are supported. On their first login in this edition, the user is asked to create a password. This is a one-time compatibility step for the educational project.

Build with MinGW g++ (C++17):
g++ -std=c++17 -Wall -Wextra main.cpp Utils.cpp PasswordUtils.cpp PermissionManager.cpp User.cpp Resource.cpp SecurityLogger.cpp UserManager.cpp RiskScoringEngine.cpp ResourceManager.cpp Threat.cpp ThreatSimulator.cpp IncidentResponseEngine.cpp SecurityReportGenerator.cpp SecurityDashboard.cpp VigilX.cpp -o VigilX.exe

Run in PowerShell:
.\VigilX.exe

To preserve data from the previous project edition, copy these files from your previous working folder into this folder BEFORE running the new executable, if they exist:
- users.txt
- resources.txt
- security_logs.txt
- incidents.txt
- permissions.txt (if you already have custom rules from this edition)

Do not overwrite or delete the older project folder. Keep this edition in its own folder as a backup-safe upgrade.

Important educational-project limitation:
This is a local console prototype, not production authentication software. SHA-256 here demonstrates salted digest storage, but production systems should use a password-specific key-derivation algorithm such as Argon2id, scrypt, bcrypt or PBKDF2, along with secure console/input handling, authorization checks on every sensitive operation, and stronger operational protections. Password characters are visible while typing in the console.
