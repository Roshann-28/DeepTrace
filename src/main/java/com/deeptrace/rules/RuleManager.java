
package com.deeptrace.rules;

import java.util.Set;
import java.util.List;
import java.util.ArrayList;
import java.util.concurrent.ConcurrentSkipListSet;
import com.deeptrace.classifier.AppType;
import java.net.IDN;
import java.util.Locale;

public final class RuleManager {

    private final Set<String> blockedIPs =
            new ConcurrentSkipListSet<>();

    private final Set<AppType> blockedApplications =
            new ConcurrentSkipListSet<>();

    private final Set<Integer> blockedPorts =
            new ConcurrentSkipListSet<>();

    private final Set<String> blockedDomains =
            new ConcurrentSkipListSet<>();

    // Validate and normalize an IPv4 address.
    private String normalizeIP(String ip) {

        if (ip == null || ip.isBlank()) {
            throw new IllegalArgumentException(
                    "IP address cannot be empty."
            );
        }

        String[] parts = ip.trim().split("\\.", -1);

        if (parts.length != 4) {
            throw new IllegalArgumentException(
                    "Invalid IPv4 address."
            );
        }

        StringBuilder normalizedIP = new StringBuilder();

        for (int i = 0; i < parts.length; i++) {

            if (parts[i].isEmpty()) {
                throw new IllegalArgumentException(
                        "Invalid IPv4 address."
                );
            }

            for (char ch : parts[i].toCharArray()) {
                if (ch < '0' || ch > '9') {
                    throw new IllegalArgumentException(
                            "Invalid IPv4 address."
                    );
                }
            }

            int octet;

            try {
                octet = Integer.parseInt(parts[i]);
            } catch (NumberFormatException e) {
                throw new IllegalArgumentException(
                        "Invalid IPv4 address."
                );
            }

            if (octet < 0 || octet > 255) {
                throw new IllegalArgumentException(
                        "IPv4 octets must be between 0 and 255."
                );
            }

            if (i > 0) {
                normalizedIP.append(".");
            }

            normalizedIP.append(octet);
        }

        return normalizedIP.toString();
    }

    // Block an IP address.
    public void blockIP(String ip) {
        String normalizedIP = normalizeIP(ip);
        blockedIPs.add(normalizedIP);
    }

    // Unblock an IP address.
    public void unblockIP(String ip) {
        String normalizedIP = normalizeIP(ip);
        blockedIPs.remove(normalizedIP);
    }

    // Check whether an IP is blocked.
    public boolean isIPBlocked(String ip) {
        String normalizedIP = normalizeIP(ip);
        return blockedIPs.contains(normalizedIP);
    }

    // Return all blocked IP addresses.
    public List<String> getBlockedIPs() {
        return new ArrayList<>(blockedIPs);
    }

    // Return the number of blocked IP addresses.
    public int getBlockedIPCount() {
        return blockedIPs.size();
    }

    // Block an application.
    public void blockApplication(AppType application) {
        if (application == null || application == AppType.UNKNOWN) {
            throw new IllegalArgumentException(
                    "A valid application type is required."
            );
        }

        blockedApplications.add(application);
    }

    // Unblock an application.
    public void unblockApplication(AppType application) {
        if (application == null) {
            throw new IllegalArgumentException(
                    "Application type cannot be null."
            );
        }

        blockedApplications.remove(application);
    }

    // Check whether an application is blocked.
    public boolean isApplicationBlocked(AppType application) {
        if (application == null) {
            return false;
        }

        return blockedApplications.contains(application);
    }

    // Return all blocked applications.
    public List<AppType> getBlockedApplications() {
        return new ArrayList<>(blockedApplications);
    }

    // Block a network port.
    public void blockPort(int port) {
        validatePort(port);
        blockedPorts.add(port);
    }

    // Unblock a network port.
    public void unblockPort(int port) {
        validatePort(port);
        blockedPorts.remove(port);
    }

    // Check whether a port is blocked.
    public boolean isPortBlocked(int port) {
        validatePort(port);
        return blockedPorts.contains(port);
    }

    // Return all blocked ports.
    public List<Integer> getBlockedPorts() {
        return new ArrayList<>(blockedPorts);
    }

    // Return the number of blocked applications.
    public int getBlockedApplicationCount() {
        return blockedApplications.size();
    }

    // Return the number of blocked ports.
    public int getBlockedPortCount() {
        return blockedPorts.size();
    }

    // Validate port range.
    private void validatePort(int port) {
        if (port < 0 || port > 65535) {
            throw new IllegalArgumentException(
                    "Port must be between 0 and 65535."
            );
        }
    }

    // Normalize and validate a domain or wildcard pattern.
    private String normalizeDomainPattern(String domain) {

        if (domain == null || domain.isBlank()) {
            throw new IllegalArgumentException(
                    "Domain cannot be empty."
            );
        }

        String value = domain.trim().toLowerCase(Locale.ROOT);

        boolean wildcard = value.startsWith("*.");

        if (value.contains("*") && !wildcard) {
            throw new IllegalArgumentException(
                    "Wildcard is only allowed at the beginning as *."
            );
        }

        if (wildcard) {
            value = value.substring(2);
        }

        // Remove a trailing DNS root dot.
        if (value.endsWith(".")) {
            value = value.substring(0, value.length() - 1);
        }

        try {
            value = IDN.toASCII(value, IDN.USE_STD3_ASCII_RULES)
                    .toLowerCase(Locale.ROOT);
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException("Invalid domain name.");
        }

        if (value.isBlank() || value.length() > 253) {
            throw new IllegalArgumentException("Invalid domain name.");
        }

        String[] labels = value.split("\\.", -1);

        for (String label : labels) {
            if (label.isEmpty()
                    || label.length() > 63
                    || label.startsWith("-")
                    || label.endsWith("-")) {
                throw new IllegalArgumentException("Invalid domain name.");
            }
        }

        return wildcard ? "*." + value : value;
    }

    // Block a domain or wildcard pattern.
    public void blockDomain(String domain) {
        blockedDomains.add(normalizeDomainPattern(domain));
    }

    // Unblock a domain or wildcard pattern.
    public void unblockDomain(String domain) {
        blockedDomains.remove(normalizeDomainPattern(domain));
    }

    // Check whether a domain matches a blocking rule.
    public boolean isDomainBlocked(String domain) {

        String normalizedDomain = normalizeDomainPattern(domain);

        // A lookup must be a domain, not a wildcard rule.
        if (normalizedDomain.startsWith("*.")) {
            throw new IllegalArgumentException(
                    "Provide a domain to check, not a wildcard pattern."
            );
        }

        for (String rule : blockedDomains) {

            if (rule.startsWith("*.")) {
                String baseDomain = rule.substring(2);

                // Wildcard matches subdomains, not the root domain.
                if (normalizedDomain.endsWith("." + baseDomain)) {
                    return true;
                }

            } else {
                // Exact rule also matches all subdomains.
                if (normalizedDomain.equals(rule)
                        || normalizedDomain.endsWith("." + rule)) {
                    return true;
                }
            }
        }

        return false;
    }

    // Return all blocked domain rules.
    public List<String> getBlockedDomains() {
        return new ArrayList<>(blockedDomains);
    }

    // Return the number of blocked domain rules.
    public int getBlockedDomainCount() {
        return blockedDomains.size();
    }


    // Remove all configured blocking rules.
    public void clearAllRules() {
        blockedIPs.clear();
        blockedApplications.clear();
        blockedPorts.clear();
        blockedDomains.clear();
    }

    // Get the total number of configured rules.
    public int getTotalRuleCount() {
        return blockedIPs.size()
                + blockedApplications.size()
                + blockedPorts.size()
                + blockedDomains.size();
    }

    // Get a snapshot of all rule counts.
    public RuleStatistics getRuleStatistics() {
        return new RuleStatistics(
                blockedIPs.size(),
                blockedApplications.size(),
                blockedPorts.size(),
                blockedDomains.size()
        );
    }


}
