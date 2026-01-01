from typing import Dict, Any
import re
from urllib.parse import urlparse


def extract_general_features(data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Extracts general and URL-level features from the JSON.
    """

    features = {}

    # URL structure analysis
    url = data.get("url", "") or ""
    parsed = urlparse(url)

    features["url_length"] = len(url)

    # Path & query analysis
    path = parsed.path or ""
    query = parsed.query or ""
    features["path_length"] = len(path)
    features["query_length"] = len(query)
    features["num_path_segments"] = path.count("/") if path else 0
    features["num_query_params"] = query.count("&") + 1 if query else 0

    match_ext = re.search(r"\.([a-zA-Z0-9]{1,6})$", path)
    features["has_file_extension"] = int(bool(match_ext))

    # Subdomain analysis
    subdomain = data.get("subdomain", "") or parsed.netloc or ""
    features["subdomain_length"] = len(subdomain)
    features["num_subdomain_levels"] = subdomain.count(".")
    features["contains_random_subdomain"] = int(bool(re.search(r"[0-9a-z]{15,}", subdomain)))

    # URL lexical indicators
    features["num_digits_in_url"] = len(re.findall(r"\d", url))
    features["num_special_chars"] = len(re.findall(r"[^a-zA-Z0-9]", url))

    # Ratio features (calculated)
    features["digit_ratio"] = round(features["num_digits_in_url"] / (features["url_length"] + 1), 3)
    features["special_char_ratio"] = round(features["num_special_chars"] / (features["url_length"] + 1), 3)

    # Derived heuristics 
    features["is_complex_url"] = int(
        features["url_length"] > 80
        or features["num_special_chars"] > 10
        or features["contains_random_subdomain"]
    )

    return features


# Quick test example
if __name__ == "__main__":
    import json

    example_data = {
        "url": "https://ctcggaptffisfgxbf3b4c7amaazzwni5rt4leqols7tyurhvbokq.ar-io.dev/FMRjAfMpUSKa4S7DwXwMADObNR2M-LJBy5fnikT1C5U",
        "tech_info": [],
        "has_path": True,
        "has_subdomain": True,
        "subdomain": "ctcggaptffisfgxbf3b4c7amaazzwni5rt4leqols7tyurhvbokq.ar-io.dev",
        "content_status": 404,
        "dns_status": "dns_resolves",
    }

    feats = extract_general_features(example_data)
    print(json.dumps(feats, indent=2))
