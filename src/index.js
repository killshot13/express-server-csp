const express = require("express");
const rateLimit = require("express-rate-limit");
const helmet = require("helmet");
const reportTo = require("report-to");
const nel = require("network-error-logging");

const app = express();

// apply recommended security measures with Helmet
app.use(
  helmet({
    contentSecurityPolicy: {
      useDefaults: false,
      directives: {
        "default-src": "'self'",
        "base-uri": "'self'",
        "block-all-mixed-content": [],
        "child-src": "'self'",
        "connect-src": [
          "'self'",
          "https://cloudflareinsights.com",
          "https://www.google-analytics.com",
          "https://p.typekit.net",
          "https://use.typekit.net"
        ],
        "font-src": [
          "'self'",
          "data:",
          "https://fonts.gstatic.com",
          "https://p.typekit.net",
          "https://use.typekit.net"
        ],
        "frame-ancestors": "'self'",
        "frame-src": [
          "'self'",
          "https://bid.g.doubleclick.net",
          "https://www.google.com"
        ],
        "img-src": [
          "'self'",
          "data:",
          "https://ssl.gstatic.com",
          "https://www.gstatic.com",
          "https://googleads.g.doubleclick.net",
          "https://www.google.com",
          "https://www.google-analytics.com"
        ],
        "manifest-src": "'self'",
        "media-src": "'self'",
        "object-src": "'self'",
        "prefetch-src": [
          "'self'",
          "https://p.typekit.net",
          "https://use.typekit.net",
          "https://ajax.cloudflare.com",
          "https://static.cloudflareinsights.com",
          "https://www.google-analytics.com",
          "https://www.googleadservices.com",
          "https://www.google.com",
          "https://www.googleadservices.com",
          "https://googleads.g.doubleclick.net",
          "https://ssl.google-analytics.com",
          "https://tagmanager.google.com",
          "https://www.googletagmanager.com"
        ],
        "script-src": [
          "'self'",
          "https://ajax.cloudflare.com",
          "https://static.cloudflareinsights.com",
          "https://www.google-analytics.com",
          "https://www.googleadservices.com",
          "https://www.google.com",
          "https://www.googleadservices.com",
          "https://googleads.g.doubleclick.net",
          "https://ssl.google-analytics.com",
          "https://tagmanager.google.com",
          "https://www.googletagmanager.com"
        ],
        "script-src-elem": [
          "'self'",
          "https://ajax.cloudflare.com",
          "https://static.cloudflareinsights.com",
          "https://www.google-analytics.com",
          "https://www.googleadservices.com",
          "https://www.google.com",
          "https://www.googleadservices.com",
          "https://googleads.g.doubleclick.net",
          "https://ssl.google-analytics.com",
          "https://tagmanager.google.com",
          "https://www.googletagmanager.com"
        ],
        "script-src-attr": [
          "'self'",
          "https://ajax.cloudflare.com",
          "https://static.cloudflareinsights.com",
          "https://www.google-analytics.com",
          "https://www.googleadservices.com",
          "https://www.google.com",
          "https://www.googleadservices.com",
          "https://googleads.g.doubleclick.net",
          "https://ssl.google-analytics.com",
          "https://tagmanager.google.com",
          "https://www.googletagmanager.com"
        ],
        "style-src": [
          "'self'",
          "https://tagmanager.google.com",
          "https://fonts.googleapis.com",
          "https://p.typekit.net",
          "https://use.typekit.net"
        ],
        "style-src-elem": [
          "'self'",
          "https://tagmanager.google.com",
          "https://fonts.googleapis.com",
          "https://p.typekit.net",
          "https://use.typekit.net"
        ],
        "style-src-attr": [
          "'self'",
          "https://tagmanager.google.com",
          "https://fonts.googleapis.com",
          "https://p.typekit.net",
          "https://use.typekit.net"
        ],
        "upgrade-insecure-requests": []
      },
      reportOnly: true,
      reportUri: "https://report-uri.com/"
    },
    crossOriginEmbedderPolicy: true,
    crossOriginOpenerPolicy: true,
    crossOriginResourcePolicy: { policy: "same-site" },
    dnsPrefetchControl: { allow: true },
    expectCt: {
      maxAge: 86400,
      enforce: true,
      reportUri: "https://report-uri.com/"
    },
    frameguard: { action: "sameorigin" },
    hidePoweredBy: false,
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    ieNoOpen: true,
    noSniff: true,
    originAgentCluster: true,
    permittedCrossDomainPolicies: { permittedPolicies: "by-content-type" },
    referrerPolicy: { policy: "no-referrer-when-downgrade" },
    xssFilter: true
  })
);
app.disable("x-powered-by");

app.use(
  reportTo({
    groups: [
      {
        group: "default",
        max_age: 31536000,
        include_subdomains: true,
        endpoints: [
          {
            url: "https://report-uri.com",
            priority: 1
          }
        ]
      }
    ]
  })
);
app.use(
  nel({
    report_to: "default",
    max_age: 31536000,
    include_subdomains: true
  })
);

const limiter = new rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 40
});

// apply rate limiter to all requests
app.use(limiter);

// configure express middleware
app.use(express.urlencoded({ extended: false }));
app.use(
  express.json({
    type: [
      "application/json",
      "application/csp-report",
      "application/reports+json"
    ]
  })
);

const PORT = process.env.PORT || 5000;

app.listen(PORT, function () {
  console.error(`Node listening on port ${PORT}`);
});
