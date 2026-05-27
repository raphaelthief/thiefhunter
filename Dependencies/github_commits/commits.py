import time
from Dependencies.displays import M, W, R, Y, G, C, handle_error
from Dependencies.get_request import get_request

# =========================
# Personal Mail Providers
# =========================
PERSONAL_PROVIDERS = {
    "gmail.com",
    "hotmail.com",
    "hotmail.fr",
    "outlook.com",
    "live.com",
    "msn.com",
    "yahoo.com",
    "yahoo.fr",
    "proton.me",
    "protonmail.com",
    "icloud.com",
    "me.com",
    "aol.com",
    "gmx.com",
    "yandex.com",
    "mail.com",
    "orange.fr",
    "free.fr",
    "laposte.net",
    "sfr.fr",
    "wanadoo.fr",
}

def is_personal_email(email: str) -> bool:
    domain = email.split("@")[-1].lower()
    return domain in PERSONAL_PROVIDERS

# =========================
# GitHub API Helpers
# =========================
def get_commits(args, username: str, repo_name: str) -> list:
    url = f"https://api.github.com/repos/{username}/{repo_name}/commits"
    response = get_request(args, url)
    if response.status_code == 200:
        return response.json()
    else:
        print(f"{G} - {W}Rate limited? {Y}[{response.status_code}]")
    return []


def get_repositories(args, username: str) -> list:
    url = f"https://api.github.com/users/{username}/repos"
    response = get_request(args, url)
    if response.status_code == 200:
        return response.json()
    return []


# =========================
# Data Extraction
# =========================
def extract_emails_from_commits(commits: list, repo_name: str) -> list:
    extracted = []
    seen_emails = set()
    for commit in commits:
        try:
            email = commit["commit"]["author"]["email"]
            author = commit.get("author")
            username = (
                author.get("login", "Unknown")
                if author
                else "Unknown"
            )

            if email not in seen_emails:
                seen_emails.add(email)
                extracted.append({
                    "email": email,
                    "username": username,
                    "repo": repo_name,
                })
        except KeyError:
            continue
    return extracted


# =========================
# Display Helpers
# =========================
def display_user_info(user_data: dict, source_url: str) -> None:
    print(f"{Y}[?] {W}Source: {source_url}")
    fields = {
        "Name": user_data.get("name"),
        "Company": user_data.get("company"),
        "Type": user_data.get("type"),
        "Location": user_data.get("location"),
        "Email": user_data.get("email"),
        "Twitter": user_data.get("twitter_username"),
        "Bio": user_data.get("bio"),
        "Repos": user_data.get("public_repos"),
        "Followers": user_data.get("followers_url"),
        "Avatar": user_data.get("avatar_url"),
        "Created at": user_data.get("created_at"),
        "Updated at": user_data.get("updated_at"),
    }

    for key, value in fields.items():
        print(f"{G}[+] {key:<11}: {W}{value}")


def display_grouped_emails(user_emails: dict) -> None:
    print(f"\n{Y}[!] Emails found grouped by username")
    for username, emails in user_emails.items():
        print(f"{G}[+] User: {Y}{username}")
        for email in emails:
            print(f"{G}    - {email}")
        print()

# =========================
# Main Features
# =========================
def extract_commits(args) -> None:
    url = f"https://api.github.com/users/{args.commits}"
    response = get_request(args, url)
    if response.status_code != 200:
        handle_error("No datas found", response.status_code)
        return

    user_data = response.json()
    if user_data.get("name") == "API rate limit exceeded":
        handle_error("GitHub API rate limit exceeded", response.status_code)
        return

    display_user_info(user_data, url)


def repos(args, username: str) -> None:
    print(f"\n{C}[+] GitHub infos")
    extract_commits(args)
    repositories = get_repositories(args, username)
    user_emails = {}
    print()
    for repo in repositories:
        repo_name = repo["name"]
        print(f"{G}[+] {W}Extracting repo: {repo_name}")
        commits = get_commits(args, args.commits, repo_name)
        emails = extract_emails_from_commits(commits, repo_name,)
        for email_info in emails:
            username = email_info["username"]
            if is_personal_email(email_info['email']):
                email_color = R
            else:
                email_color = C
            
            formatted_email = (
                f"{email_color}{email_info['email']} "
                f"{W}(Repo: {email_info['repo']})"
            )
            user_emails.setdefault(username, []).append(formatted_email)
        time.sleep(0.7)
    display_grouped_emails(user_emails)