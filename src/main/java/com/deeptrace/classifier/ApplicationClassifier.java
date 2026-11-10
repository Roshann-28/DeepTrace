
package com.deeptrace.classifier;

import com.deeptrace.extractor.ApplicationMetadata;

import java.util.Locale;

public final class ApplicationClassifier {

    public AppType classify(ApplicationMetadata metadata) {

        // No metadata means we cannot identify the application.
        if (metadata == null) {
            return AppType.UNKNOWN;
        }

        String domain = metadata.domain()
                .trim()
                .toLowerCase(Locale.ROOT);

        String protocol = metadata.applicationProtocol()
                .trim()
                .toUpperCase(Locale.ROOT);

        // First, identify the application using its domain.
        AppType application = classifyDomain(domain);

        if (application != AppType.UNKNOWN) {
            return application;
        }

        // If the domain is not recognized,
        // fall back to the available protocol.
        return classifyProtocol(protocol);
    }

    private AppType classifyDomain(String domain) {

        if (matchesDomain(domain, "youtube.com")
                || matchesDomain(domain, "youtube-nocookie.com")
                || matchesDomain(domain, "youtu.be")
                || matchesDomain(domain, "googlevideo.com")) {
            return AppType.YOUTUBE;
        }

        if (matchesDomain(domain, "google.com")
                || matchesDomain(domain, "google.co.in")
                || matchesDomain(domain, "googleapis.com")
                || matchesDomain(domain, "gstatic.com")) {
            return AppType.GOOGLE;
        }

        if (matchesDomain(domain, "facebook.com")
                || matchesDomain(domain, "fb.com")
                || matchesDomain(domain, "fbcdn.net")) {
            return AppType.FACEBOOK;
        }

        if (matchesDomain(domain, "instagram.com")
                || matchesDomain(domain, "cdninstagram.com")) {
            return AppType.INSTAGRAM;
        }

        if (matchesDomain(domain, "twitter.com")
                || matchesDomain(domain, "x.com")
                || matchesDomain(domain, "t.co")) {
            return AppType.TWITTER;
        }

        if (matchesDomain(domain, "netflix.com")
                || matchesDomain(domain, "nflxvideo.net")) {
            return AppType.NETFLIX;
        }

        if (matchesDomain(domain, "amazon.com")
                || matchesDomain(domain, "amazon.in")
                || matchesDomain(domain, "amazonaws.com")) {
            return AppType.AMAZON;
        }

        if (matchesDomain(domain, "microsoft.com")
                || matchesDomain(domain, "live.com")
                || matchesDomain(domain, "office.com")) {
            return AppType.MICROSOFT;
        }

        if (matchesDomain(domain, "apple.com")
                || matchesDomain(domain, "icloud.com")) {
            return AppType.APPLE;
        }

        if (matchesDomain(domain, "whatsapp.com")
                || matchesDomain(domain, "whatsapp.net")) {
            return AppType.WHATSAPP;
        }

        if (matchesDomain(domain, "telegram.org")
                || matchesDomain(domain, "t.me")) {
            return AppType.TELEGRAM;
        }

        if (matchesDomain(domain, "tiktok.com")
                || matchesDomain(domain, "tiktokcdn.com")) {
            return AppType.TIKTOK;
        }

        if (matchesDomain(domain, "spotify.com")
                || matchesDomain(domain, "scdn.co")) {
            return AppType.SPOTIFY;
        }

        if (matchesDomain(domain, "zoom.us")
                || matchesDomain(domain, "zoom.com")) {
            return AppType.ZOOM;
        }

        if (matchesDomain(domain, "discord.com")
                || matchesDomain(domain, "discord.gg")
                || matchesDomain(domain, "discordapp.com")) {
            return AppType.DISCORD;
        }

        if (matchesDomain(domain, "github.com")
                || matchesDomain(domain, "githubusercontent.com")) {
            return AppType.GITHUB;
        }

        if (matchesDomain(domain, "cloudflare.com")
                || matchesDomain(domain, "cloudflare-dns.com")) {
            return AppType.CLOUDFLARE;
        }

        return AppType.UNKNOWN;
    }

    private boolean matchesDomain(String domain, String knownDomain) {

        return domain.equals(knownDomain)
                || domain.endsWith("." + knownDomain);
    }

    private AppType classifyProtocol(String protocol) {

        return switch (protocol) {
            case "HTTP" -> AppType.HTTP;
            case "HTTPS" -> AppType.HTTPS;
            case "TLS" -> AppType.TLS;
            case "DNS" -> AppType.DNS;
            case "QUIC" -> AppType.QUIC;
            default -> AppType.UNKNOWN;
        };
    }
}
