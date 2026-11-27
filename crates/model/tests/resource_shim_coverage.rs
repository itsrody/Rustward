//! Coverage checks for adblock-rust's informal "shim" resources.
//!
//! adblock-rust has no shim registry: `web_accessible_resources` files referenced by uBO's
//! `redirect-resources.js` become redirectable `Resource`s, and scriptlet files become injection
//! `Resource`s. The expected sets below are transcribed from the same pinned upstream commits as
//! the verified snapshots, so a pin update must update this test too.

use adblock::resources::{MimeType, ResourceType};
use model::{
    ScriptletGrade,
    resources::{
        ContentEncoding, OfficialResource, ResourceCatalog, ResourceKind, ResourceSnapshot,
    },
};
use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
};

const UBO_COMMIT: &str = "3cca944b4a4c5f3473d6cb7153e6fb99b5f7d1db";
const UBO_SHA256: &str = "b5c816d61ec4201175899d17637c785d81e3de530fee949c1bf780b4ffd9df5b";
const BRAVE_COMMIT: &str = "b84ad0fd6663a88c1402bc06a4abd5ab8be8fb3c";
const BRAVE_SHA256: &str = "31d6bdd604b45e155d1093064a082b8f93ca63650be4bbb3e338a7a60d485053";

/// adblock-rust skips mapping entries with `params`, so `click2load.html` at the pinned uBO
/// commit is intentionally absent. These are the other 47 entries.
const UBO_REDIRECT_RESOURCES: &[&str] = &[
    "1x1.gif",
    "2x2.png",
    "3x2.png",
    "32x32.png",
    "amazon_ads.js",
    "amazon_apstag.js",
    "ampproject_v0.js",
    "adthrive_abd.js",
    "chartbeat.js",
    "doubleclick_instream_ad_status.js",
    "empty",
    "fingerprint2.js",
    "fingerprint3.js",
    "freestar_pubfig.js",
    "google-analytics_analytics.js",
    "google-analytics_cx_api.js",
    "google-analytics_ga.js",
    "google-analytics_inpage_linkid.js",
    "google-ima.js",
    "google-ima-dai.js",
    "googlesyndication_adsbygoogle.js",
    "googletagservices_gpt.js",
    "hd-main.js",
    "nitropay_ads.js",
    "nobab2.js",
    "noeval.js",
    "noeval-silent.js",
    "nofab.js",
    "noop-0.1s.mp3",
    "noop-0.5s.mp3",
    "noop-1s.mp4",
    "noop.css",
    "noop.html",
    "noop.js",
    "noop.json",
    "noop.txt",
    "noop-vast2.xml",
    "noop-vast3.xml",
    "noop-vast4.xml",
    "noop-vmap1.xml",
    "outbrain-widget.js",
    "piano-analytics.js",
    "popads.js",
    "popads-dummy.js",
    "prebid-ads.js",
    "scorecardresearch_beacon.js",
    "sensors-analytics.js",
];

/// Every `alias` field in the pinned `redirect-resources.js`, paired with its canonical name.
const UBO_REDIRECT_ALIASES: &[(&str, &str)] = &[
    ("1x1-transparent.gif", "1x1.gif"),
    ("2x2-transparent.png", "2x2.png"),
    ("3x2-transparent.png", "3x2.png"),
    ("32x32-transparent.png", "32x32.png"),
    ("amazon-adsystem.com/aax2/amzn_ads.js", "amazon_ads.js"),
    ("ampproject.org/v0.js", "ampproject_v0.js"),
    ("static.chartbeat.com/chartbeat.js", "chartbeat.js"),
    (
        "doubleclick.net/instream/ad_status.js",
        "doubleclick_instream_ad_status.js",
    ),
    (
        "google-analytics.com/analytics.js",
        "google-analytics_analytics.js",
    ),
    ("googletagmanager_gtm.js", "google-analytics_analytics.js"),
    (
        "googletagmanager.com/gtm.js",
        "google-analytics_analytics.js",
    ),
    (
        "google-analytics.com/cx/api.js",
        "google-analytics_cx_api.js",
    ),
    ("google-analytics.com/ga.js", "google-analytics_ga.js"),
    (
        "google-analytics.com/inpage_linkid.js",
        "google-analytics_inpage_linkid.js",
    ),
    ("google-ima3", "google-ima.js"),
    ("google-ima3-dai", "google-ima-dai.js"),
    (
        "googlesyndication.com/adsbygoogle.js",
        "googlesyndication_adsbygoogle.js",
    ),
    (
        "googlesyndication-adsbygoogle",
        "googlesyndication_adsbygoogle.js",
    ),
    ("googletagservices.com/gpt.js", "googletagservices_gpt.js"),
    ("googletagservices-gpt", "googletagservices_gpt.js"),
    ("silent-noeval.js", "noeval-silent.js"),
    ("fuckadblock.js-3.2.0", "nofab.js"),
    ("noopmp3-0.1s", "noop-0.1s.mp3"),
    ("abp-resource:blank-mp3", "noop-0.1s.mp3"),
    ("noopmp4-1s", "noop-1s.mp4"),
    ("abp-resource:blank-mp4", "noop-1s.mp4"),
    ("noopframe", "noop.html"),
    ("noopjs", "noop.js"),
    ("abp-resource:blank-js", "noop.js"),
    ("noopjson", "noop.json"),
    ("nooptext", "noop.txt"),
    ("noopvast-2.0", "noop-vast2.xml"),
    ("noopvast-3.0", "noop-vast3.xml"),
    ("noopvast-4.0", "noop-vast4.xml"),
    ("noop-vmap1.0.xml", "noop-vmap1.xml"),
    ("noopvmap-1.0", "noop-vmap1.xml"),
    ("widgets.outbrain.com/outbrain.js", "outbrain-widget.js"),
    ("popads.net.js", "popads.js"),
    ("prevent-popads-net.js", "popads.js"),
    (
        "scorecardresearch.com/beacon.js",
        "scorecardresearch_beacon.js",
    ),
];

/// All 25 entries of Brave's pinned `dist/resources.json`. Brave contributes scriptlets only.
const BRAVE_RESOURCES: &[&str] = &[
    "ampconsent-reject-unblock.js",
    "async-sugarcoat-04394153a7ce417b88e3fe1790a4e6a269bfebe5.js",
    "async-sugarcoat-8a459c41783885dc83d30f5b7da2359091f4e607.js",
    "brave-auto-pip.js",
    "brave-disable-pageview-api.js",
    "brave-fix.js",
    "brave-google-maps-fix.js",
    "brave-video-bg-play-update.js",
    "brave-video-bg-play.js",
    "brave-youtube-navigation-fix.js",
    "brave-youtube-playback-speed-fix.js",
    "brave-youtube-theater-fix.js",
    "brave-yt-sabr-fix.js",
    "de-amp.js",
    "fundingchoices-reject.js",
    "ketch-reject-unblock.js",
    "optimizely.js",
    "sourcepoint-reject.js",
    "touch-fix.js",
    "transcend-reject.js",
    "trusted_types.js",
    "vaft-ublock-origin.js",
    "video-swap-new-ublock-origin.js",
    "zdconsent-accept.js",
    "zdconsent-reject.js",
];

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn load_snapshot(name: &str, commit: &str, sha256: &str) -> ResourceSnapshot {
    let snapshot =
        ResourceSnapshot::load_verified(&root().join(format!("config/resources/{name}")), sha256)
            .unwrap_or_else(|error| panic!("load {name}: {error:#}"));
    assert_eq!(snapshot.commit, commit);
    snapshot
}

fn ubo_catalog() -> ResourceCatalog {
    load_snapshot("ubo-official.json", UBO_COMMIT, UBO_SHA256)
        .into_catalog()
        .expect("uBO catalog")
}

fn synthetic(name: &str, kind: ResourceKind) -> OfficialResource {
    OfficialResource {
        name: name.to_string(),
        aliases: Vec::new(),
        grade: ScriptletGrade::Standard,
        kind,
        content: "void 0".to_string(),
        content_encoding: ContentEncoding::Text,
        dependencies: Vec::new(),
        permission: 0,
        digest: [0; 32],
    }
}

#[test]
fn engine_resource_types_and_mime_variants_are_all_representable() {
    let cases = [
        (
            "template.js",
            ResourceKind::Template,
            ResourceType::Template,
        ),
        (
            "script.js",
            ResourceKind::ApplicationJavascript,
            ResourceType::Mime(MimeType::ApplicationJavascript),
        ),
        (
            "fn.js",
            ResourceKind::FnJavascript,
            ResourceType::Mime(MimeType::FnJavascript),
        ),
        (
            "shim.css",
            ResourceKind::Other,
            ResourceType::Mime(MimeType::TextCss),
        ),
        (
            "shim.gif",
            ResourceKind::Other,
            ResourceType::Mime(MimeType::ImageGif),
        ),
        (
            "shim.html",
            ResourceKind::Other,
            ResourceType::Mime(MimeType::TextHtml),
        ),
        (
            "shim.json",
            ResourceKind::Other,
            ResourceType::Mime(MimeType::ApplicationJson),
        ),
        (
            "shim.mp3",
            ResourceKind::Other,
            ResourceType::Mime(MimeType::AudioMp3),
        ),
        (
            "shim.mp4",
            ResourceKind::Other,
            ResourceType::Mime(MimeType::VideoMp4),
        ),
        (
            "shim.png",
            ResourceKind::Other,
            ResourceType::Mime(MimeType::ImagePng),
        ),
        (
            "shim.txt",
            ResourceKind::Other,
            ResourceType::Mime(MimeType::TextPlain),
        ),
        (
            "shim.xml",
            ResourceKind::Other,
            ResourceType::Mime(MimeType::TextXml),
        ),
        (
            "shim.unknown",
            ResourceKind::Other,
            ResourceType::Mime(MimeType::Unknown),
        ),
        (
            "empty",
            ResourceKind::Other,
            ResourceType::Mime(MimeType::Unknown),
        ),
    ];
    for (name, kind, expected) in cases {
        assert_eq!(
            synthetic(name, kind).engine_resource().kind,
            expected,
            "{name}"
        );
    }

    // Engine-side capabilities are listed here so a mapping change cannot silently widen or
    // narrow which resource classes D11 can realize.
    assert!(!ResourceType::Template.supports_redirect());
    assert!(!ResourceType::Mime(MimeType::FnJavascript).supports_redirect());
    assert!(ResourceType::Mime(MimeType::ApplicationJavascript).supports_redirect());
    assert!(ResourceType::Mime(MimeType::Unknown).supports_redirect());
    assert!(ResourceType::Template.supports_scriptlet_injection());
    assert!(ResourceType::Mime(MimeType::ApplicationJavascript).supports_scriptlet_injection());
    assert!(!ResourceType::Mime(MimeType::FnJavascript).supports_scriptlet_injection());
}

#[test]
fn pinned_ubo_redirect_resources_are_all_present() {
    assert_eq!(UBO_REDIRECT_RESOURCES.len(), 47);
    let catalog = ubo_catalog();
    for name in UBO_REDIRECT_RESOURCES {
        let resource = catalog.find(name).unwrap_or_else(|| {
            panic!("uBO redirect resource {name} missing from official snapshot")
        });
        assert_eq!(resource.name, *name);
        // uBO marks google-ima-dai.js `requiresTrust: true`, so its redirect token is
        // rejected from untrusted lists. The snapshot records that as the engine trust
        // bit; every other pinned redirect resource stays permission 0.
        let expected_permission = if *name == "google-ima-dai.js" { 1 } else { 0 };
        assert_eq!(
            resource.permission, expected_permission,
            "{name} permission"
        );
        assert!(
            resource.engine_resource().kind.supports_redirect(),
            "{name} maps to a non-redirectable engine kind"
        );
        assert!(
            catalog.dependency_closure(name).is_ok(),
            "{name} has an unresolved dependency"
        );
    }

    // adblock-rust ignores this mapping entry because it declares `params`.
    assert!(catalog.find("click2load.html").is_none());
}

#[test]
fn pinned_ubo_redirect_aliases_resolve_to_canonical_names() {
    assert_eq!(UBO_REDIRECT_ALIASES.len(), 40);
    let catalog = ubo_catalog();
    for (alias, canonical) in UBO_REDIRECT_ALIASES {
        let resource = catalog
            .find(alias)
            .unwrap_or_else(|| panic!("uBO redirect alias {alias} missing from official snapshot"));
        assert_eq!(resource.name, *canonical, "alias {alias}");
    }

    // uBO rejects `redirect=google-ima3-dai` from an untrusted list; the alias must
    // inherit the canonical resource's trust requirement rather than appearing usable.
    let dai = catalog
        .find("google-ima3-dai")
        .expect("google-ima3-dai alias");
    assert_eq!(dai.name, "google-ima-dai.js");
    assert_eq!(dai.permission, 1);
}

#[test]
fn pinned_brave_scriptlets_are_all_present() {
    assert_eq!(BRAVE_RESOURCES.len(), 25);
    let snapshot = load_snapshot("brave-official.json", BRAVE_COMMIT, BRAVE_SHA256);
    let names: BTreeSet<_> = snapshot
        .resources
        .iter()
        .map(|resource| resource.name.clone())
        .collect();
    assert_eq!(names.len(), BRAVE_RESOURCES.len());
    for name in BRAVE_RESOURCES {
        assert!(
            names.contains(*name),
            "Brave scriptlet {name} missing upstream snapshot"
        );
    }

    let catalog = snapshot.into_catalog().expect("Brave catalog");
    for name in BRAVE_RESOURCES {
        let resource = catalog
            .find(name)
            .unwrap_or_else(|| panic!("Brave scriptlet {name} missing from catalog"));
        assert_eq!(resource.grade, ScriptletGrade::Standard);
        assert_eq!(resource.permission, 0);
        assert!(
            resource
                .engine_resource()
                .kind
                .supports_scriptlet_injection(),
            "{name} maps to a non-injectable engine kind"
        );
        assert!(
            catalog.dependency_closure(name).is_ok(),
            "{name} has an unresolved dependency"
        );
    }
}
