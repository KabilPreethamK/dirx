import re
def is_valid_domain(domain):
    """Check if the input is a valid domain name."""
    # Regular expression for validating a domain name
    domain_pattern = re.compile(
        r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.'  # Start with a valid character
        r'([A-Za-z]{2,}|[A-Za-z0-9-]{1,}\.[A-Za-z]{2,})$'  # Top-level domain
    )
    return bool(domain_pattern.match(domain))



print(is_valid_domain("192.168.0.2"))