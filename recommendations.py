def get_recommendations(results, ports):

    recommendations = []

    # Header recommendations
    if results.get("Content-Security-Policy") == "Missing":
        recommendations.append(
            "Implement Content-Security-Policy (CSP) to prevent XSS attacks."
        )

    if results.get("Strict-Transport-Security") == "Missing":
        recommendations.append(
            "Enable Strict-Transport-Security (HSTS) for secure HTTPS connections."
        )

    if results.get("X-Content-Type-Options") == "Missing":
        recommendations.append(
            "Configure X-Content-Type-Options to prevent MIME-type sniffing."
        )

    # Port recommendations
    for port in ports:
        if port["port"] == 22:
            recommendations.append(
                "Restrict SSH access if it is not publicly required."
            )

    if not recommendations:
        recommendations.append(
            "No major issues detected. Continue regular security monitoring."
        )

    return recommendations