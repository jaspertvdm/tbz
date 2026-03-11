# 📦 TIBET-zip (TBZ)
**Deterministic, block-level authenticated compression for the Zero-Trust era.**

[![Rust](https://img.shields.io/badge/rust-pure-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-architecture_draft-blue.svg)]()
[![License](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)]()

De huidige digitale infrastructuur leunt op blind vertrouwen. Klassieke archiefformaten (`.zip`, `.tar.gz`) zijn semantisch leeg: ze bevatten geen cryptografisch bewijs van herkomst, intentie of autorisatie. Dit leidt tot catastrofale kwetsbaarheden zoals "Zombie ZIP" exploits en AI-model supply chain attacks.

**TBZ (TIBET-zip)** herontwerpt datacompressie vanuit de *First Principles* van Zero-Trust. Het is geen nieuw compressie-algoritme, maar een semantische, cryptografische beveiligingsschil rondom `zstd`.

## ✨ Killer Features

* 🚀 **Streaming Validation (Fail-Fast):** Blokken worden on-the-fly gedecomprimeerd en cryptografisch gevalideerd. Een gemanipuleerd blok stopt het proces direct; de malware raakt het uitvoerbare geheugen nooit.
* 🛡️ **eBPF TIBET Airlock:** Een meedogenloze kernel-level quarantaine-omgeving. Bestanden worden in een geïsoleerde buffer geëvalueerd en bij falen overschreven met een binaire `0x00 wipe`.
* 🪪 **JIS Sector Autorisatie:** Eén archiefbestand, meerdere views. Bepaal via cryptografische claims (JIS) wie welk deel van het archief mag uitpakken (bijv. publieke code vs. geheime keys).
* 🪞 **Transparency Mirror:** Een gedistribueerde (DHT) database die cryptografische vingerafdrukken van bekende packages verifieert, gebouwd op `sled`.
* 🦀 **100% Pure Rust:** Geheugenveilig, razendsnel, en platform-onafhankelijk. Geen kwetsbare C/C++ dependencies.

## 🏗️ Architectuur

TBZ vervangt 'alles-of-niets' decompressie door een gelaagde *streaming pipeline*. Elk blok in een `.tbz` archief bevat zijn eigen TIBET-token (provenance) en JIS-autorisatie.

```text
 Netwerk             TIBET Airlock (eBPF)       Bestandssysteem
    │                      │                       │
    ├── BLOK 0 ──────► manifest lezen              │
    │                      │ check JIS levels      │
    │                      │                       │
    ├── BLOK 1 ──────► decompress + validate       │
    │                      │ JIS authorize?        │
    │                      │ ✓ ─────────────────► pad toewijzen
    │                      │ ✗ ── 0x00 wipe        │
    │                      │                       │
    ├── BLOK 2 ──────► decompress (parallel!)      │
  (downloading)            │ ...                   │

Meer weten? Lees het volledige Architecture Design Document (ADD) in deze repository.

💻 Developer Workflow (Concept)

Veranker je repository identiteit eenmalig in GitHub (.jis.json), en pack je archieven met onweerlegbare provenance:
📂 Workspace Structuur

Het project is opgedeeld in modulaire, testbare Rust crates:

    tbz-core: De kernlogica. Zstd frames, TIBET-envelopes, en block headers.

    tbz-cli: De command-line interface (tbz pack, tbz unpack).

    tbz-airlock: De userspace manager en eBPF kernel hooks (via Aya).

    tbz-mirror: De lokale sled cache en DHT-client voor supply-chain verificatie.

    tbz-jis: Parser voor .jis.json en de identiteit-protocollen.

🤝 Bijdragen

Dit protocol is momenteel in de ontwerpfase (Draft). Issues en Pull Requests gericht op de architectuur, edge-cases en implementatiedetails in Rust zijn meer dan welkom!
