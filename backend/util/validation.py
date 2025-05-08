import random
import string



def validate_password_strength(password):
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if not any(char.isupper() for char in password):
        return False, "Password must include at least one uppercase letter."
    if not any(char.islower() for char in password):
        return False, "Password must include at least one lowercase letter."
    if not any(char.isdigit() for char in password):
        return False, "Password must include at least one number."
    if not any(char in "!@#$%^&*()_+-=~" for char in password):
        return False, "Password must include at least one special character."
    return True, "Password is strong."



#Random password generator
def generate_strong_password(length=12):
    if length < 8:
        length = 8  # Enforce minimum length

    characters = string.ascii_letters + string.digits + "!@#$%^&*()_+-=~"
    password = ''.join(random.choice(characters) for _ in range(length))
    return password