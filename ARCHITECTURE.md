Architecture Design Document: TIBET-zip (TBZ) & The Provenance Ecosystem

Auteur: J. van de Meent, Humotica
Co-auteur: Root AI (Claude Opus 4), HumoticaOS
Status: Concept / Draft
Datum: 2026-03-11
Technologie: TIBET, JIS, zstd
Licentie: MIT / Apache 2.0

===============================================================================

1. Introductie & Probleemstelling

De huidige digitale infrastructuur leunt op 'blind vertrouwen'. Archiefformaten
zoals .zip en .tar.gz (ontworpen in de jaren '90) zijn semantisch leeg; ze
bevatten geen cryptografisch bewijs van herkomst, intentie of autorisatie. Dit
leidt tot fundamentele kwetsbaarheden in moderne IT-omgevingen en AI-supply
chains:

  De "Zombie ZIP" Crisis (CVE-2026-0866): Antivirus- en EDR-systemen scannen
  bestanden op basis van onbetrouwbare headers. Kwaadaardige payloads worden
  blindelings door de decompressie-engine in het geheugen geladen voordat ze
  gevalideerd worden.

  AI Model Supply Chain Attacks: Gigantische AI-modellen (zoals GGUF-bestanden)
  worden in hun geheel in het geheugen geladen. Er is geen granulaire,
  block-level garantie dat de gewichten van het model niet onderweg zijn
  gemanipuleerd.

  Data Silo's & Privacy: Het is momenteel onmogelijk om één groot
  archiefbestand te delen waarbij verschillende actoren (via Role-Based Access)
  slechts toegang hebben tot specifieke delen van de gedecomprimeerde data.

===============================================================================

2. De Oplossing: Het TIBET Provenance Ecosysteem

Om de overstap te maken van reactieve blacklisting naar deterministische
whitelisting, introduceert dit document een gelaagde architectuur. Bestaande
decompressie wordt vervangen door geauthenticeerde, streaming decompressie,
aangedreven door het TIBET-protocol en JIS identiteiten.

Het ecosysteem bestaat uit drie onlosmakelijk verbonden lagen:

  ┌──────────────────────┬──────────────────────────────┬──────────────────┐
  │ Laag                 │ Functie                      │ Analogie         │
  ├──────────────────────┼──────────────────────────────┼──────────────────┤
  │ 1. TBZ Formaat       │ Block-level trusted          │ Het bestands-    │
  │                      │ compression (zstd + TIBET)   │ formaat          │
  ├──────────────────────┼──────────────────────────────┼──────────────────┤
  │ 2. TIBET Airlock     │ Sandbox decompressie met     │ De airbag        │
  │                      │ cryptografische 0x00 wipe    │                  │
  ├──────────────────────┼──────────────────────────────┼──────────────────┤
  │ 3. Transparency      │ DHT-based gedistribueerde    │ De decentrale    │
  │    Mirror            │ binary transparency log      │ trust-database   │
  └──────────────────────┴──────────────────────────────┴──────────────────┘

===============================================================================

3. Architectuur van het TBZ Formaat

Het .tza (TIBET Zip Archive) formaat is geen nieuw compressie-algoritme, maar een
semantische beveiligingsschil rondom bewezen technologie (zstd). Het maakt
gebruik van onafhankelijke frames om streaming validation mogelijk te maken.

3.1 Streaming Flow & Fail-Fast Mechanisme

In tegenstelling tot klassieke archieven, waarbij het gehele bestand of archief
moet worden ingeladen voor verificatie, valideert TBZ de data asynchroon en
per blok.

  Blok 0 (Het Manifest): Een cryptografisch ondertekende index
  (JIS-autorisatie level 0). Dit blok vertelt de parser vooraf hoeveel
  blokken er zijn, en welke JIS-clearance nodig is per sector.

  Blok 1 tot N (De Data): Elk blok bevat zijn eigen TIBET-token
  (ERIN, ERAAN, EROMHEEN, ERACHTER) en de gecomprimeerde payload.

  Fail-Fast: Als de wiskundige hash of de JIS-intentie van Blok 2 niet
  klopt, stopt de decompressie onmiddellijk. Het corrupte blok raakt het
  werkgeheugen nooit als uitvoerbare code.

3.2 Blok Structuur

  Elk TBZ blok volgt deze structuur:

  ┌─────────────────────────────────────────────────┐
  │ BLOCK HEADER                                    │
  │   magic: 0x54425A  ("TBZ")                      │
  │   version: u8                                   │
  │   block_index: u32                              │
  │   block_type: u8 (manifest | data | nested)     │
  │   jis_level: u8                                 │
  │   uncompressed_size: u64                        │
  │   compressed_size: u64                          │
  ├─────────────────────────────────────────────────┤
  │ TIBET ENVELOPE                                  │
  │   erin: content hash + type declaration         │
  │   eraan: dependencies (parent blocks)           │
  │   eromheen: context (origin, timestamp)         │
  │   erachter: intent (why this block exists)      │
  ├─────────────────────────────────────────────────┤
  │ PAYLOAD                                         │
  │   zstd-compressed data (single frame)           │
  ├─────────────────────────────────────────────────┤
  │ SIGNATURE                                       │
  │   Ed25519 over header + envelope + payload      │
  │   JIS bilateral consent token                   │
  └─────────────────────────────────────────────────┘

3.3 Visuele Weergave van de TBZ Structuur

  ┌─────────────────────────────────────────────────┐
  │ TBZ Bestand                                     │
  ├─────────────────────────────────────────────────┤
  │ BLOK 0: Manifest                                │
  │ ┌─────────────────────────────────────────────┐ │
  │ │ Autorisatie: Level 0 (publiek)              │ │
  │ │ Cryptografisch ondertekend (TIBET+JIS)      │ │
  │ │ Inhoud:                                     │ │
  │ │   - Aantal blokken                          │ │
  │ │   - Per blok: type, grootte, JIS-level      │ │
  │ │   - Vereiste autorisaties per sector        │ │
  │ │   - Structuur: TBZ (Flat) of TBZ-deep       │ │
  │ │   - Totale uitgepakte grootte (bombprotectie)│ │
  │ │   - TBZ versie + capabilities               │ │
  │ └─────────────────────────────────────────────┘ │
  ├─────────────────────────────────────────────────┤
  │ BLOK 1: Data (Streaming start)                  │
  │ ┌─────────────────────────────────────────────┐ │
  │ │ TIBET: ERIN (payload) + ERAAN (identiteit)  │ │
  │ │ JIS: autorisatie-level + intent             │ │
  │ │ Payload: zstd-compressed data               │ │
  │ │ Signature: cryptografische handtekening     │ │
  │ └─────────────────────────────────────────────┘ │
  ├─────────────────────────────────────────────────┤
  │ BLOK 2: Data (binnenkomend terwijl blok 1       │
  │          al in de Airlock valideert)             │
  │ └── zelfde structuur                            │
  ├─────────────────────────────────────────────────┤
  │ BLOK N: ...                                     │
  └─────────────────────────────────────────────────┘

3.4 Streaming Pipeline

  Netwerk            TIBET Airlock          Bestandssysteem
     │                    │                      │
     ├── BLOK 0 ──────► manifest lezen           │
     │                    │ parse index           │
     │                    │ check JIS levels      │
     │                    │                      │
     ├── BLOK 1 ──────► decompress              │
     │                    │ TIBET validate        │
     │                    │ JIS authorize?        │
     │                    │ ✓ ─────────────────► pad toewijzen
     │                    │ ✗ ── 0x00 wipe       │
     │                    │                      │
     ├── BLOK 2 ──────► decompress (parallel!)  │
     │  (downloading)     │ validate + authorize  │
     │                    │ ...                   │

  Blok N valideert terwijl blok N+1 downloadt. Echte pipeline.

3.5 Nested Blocks: TBZ-deep (Matroesjka)

  Een blok mag een genest TBZ archief bevatten. Om zip-bommen te voorkomen
  gelden strikte regels:

  1. Manifest MOET nesting declareren (geen verrassingen)
  2. Maximale nesting-diepte gedefinieerd in root manifest
  3. Elke geneste TBZ doorloopt volledige TIBET validatie (TIBET-pol)
  4. Totale uitgepakte grootte over alle levels MOET gedeclareerd zijn
  5. Airlock buffer limiet — overschrijding = STOP

===============================================================================

4. De TIBET Airlock (Quarantine Buffer)

De Airlock is de gesandboxte decompressie-omgeving. Vernoemd naar een echte
luchtsluis: niets komt erdoor zonder de checks te passeren.

4.1 Concept

Voor achterwaartse compatibiliteit met onveilige formaten (.zip, .tar.gz)
functioneert de TIBET Airlock als een meedogenloze grenscontrole.

  - Onbekende archieven worden uitsluitend in een geïsoleerde RAM-omgeving
    (de Quarantine Buffer) uitgepakt.
  - Het systeem voert een validatie uit tegen de Transparency Mirror.
  - Bij een succesvolle validatie wordt de data on-the-fly omgezet naar een
    veilig .tza formaat, getekend met de JIS-identiteit van de lokale sandbox.
  - Bij falen (bijv. een Zip-bomb of Zombie ZIP manipulatie) wordt de buffer
    direct overschreven met nullen (0x00 wipe) om geheugen-exploits te
    voorkomen. Het bestandssysteem (de harde schijf) wordt nooit geraakt.

4.2 Lifecycle

  1. ALLOCATE  — Reserveer quarantine buffer (grootte uit manifest)
  2. RECEIVE   — Stream blok naar Airlock
  3. VALIDATE  — Check TIBET provenance + JIS autorisatie
  4. DECIDE    — Geautoriseerd? → kopieer naar bestandssysteem-pad
                 Niet geautoriseerd? → wipe buffer (0x00)
  5. RELEASE   — Zero-fill gehele Airlock regio, deallocate

4.3 Eigenschappen

  - Dedicated tijdelijk hardware/geheugen-regio
  - Binaire wipe (0x00) na elk blok, ongeacht uitkomst
  - Geen bestandssysteem-pad tot expliciete autorisatie
  - Grootte-gelimiteerd: Airlock weigert blokken boven gedeclareerde grootte
  - Tijd-gelimiteerd: Airlock auto-wiped na configureerbare timeout

4.4 Legacy Formaat Afhandeling

  Wanneer de TBZ-tool een niet-TBZ archief tegenkomt (.tar.gz, .zip, .rar):

  1. Herkenning: "dit is geen TBZ"
  2. Uitpakken in Airlock (quarantine, niet je systeem)
  3. Valideren tegen Transparency Mirror
  4. Ondertekenen met TIBET + JIS
  5. Resultaat: vertrouwd TBZ her-pakket, of quarantine-alert

  De TBZ-tool is een goede burger. Hij handelt je legacy formaten af,
  maar behandelt ze standaard als onvertrouwd.

===============================================================================

5. De TIBET Transparency Mirror

De spiegel is de ruggengraat van het Zero Trust Ingestion model. Het is een
decentrale, Distributed Hash Table (DHT) netwerklaag.

5.1 Per Package Entry

  Het netwerk slaat de cryptografische vingerafdrukken en TIBET-handtekeningen
  op van bekende, veilige bestanden (gekoppeld aan officiële JIS-identiteiten,
  zoals Canonical of Python Software Foundation).

  Per package/archief:
  - Hash van origineel archief
  - TIBET provenance chain
  - Reproducible build attestation
  - Bekende kwetsbaarheden
  - JIS autorisatie-historie
  - Community attestations (web of trust)

5.2 Bronnen

  Lokale Airlocks kunnen in milliseconden verifiëren of de wiskundige
  structuur van een uitgepakt bestand overeenkomt met de legitieme intentie
  van de originele maker.

  De mirror aggregeert trust-signalen uit bestaande infrastructuur:

  - apt repository hashes
  - PyPI package hashes + signatures
  - npm registry integrity checksums
  - Docker image digests
  - GitHub release attestations
  - Sigstore/cosign transparency logs
  - Community attestations

5.3 Groeimodel

  De mirror begint klein en groeit organisch. Elke keer dat iemand een
  package uitpakt via de TBZ-tool, wordt het hash + validatie-resultaat
  bijgedragen aan de DHT. Zoals Bitcoin-nodes de chain opbouwen — iedereen
  draagt bij, iedereen profiteert.

5.4 Operaties

  Iedereen kan:
    - LEZEN      — verifieer elk package tegen de mirror
    - ATTESTEREN — draag validatie-resultaten bij
    - SPIEGELEN  — draai een node, vergroot resilience
    - CHALLENGEN — betwist een attestation (met bewijs)

===============================================================================

6. Use Cases

6.1 Supply Chain Security

  Het zombie-zip probleem: bedrijven downloaden packages, unzippen, en
  deployen per ongeluk malware. TBZ valideert elk blok voordat het de
  schijf raakt. Fail-fast. Geen bidden meer na `tar xzf`.

6.2 Database Sector Access

  Een gecomprimeerde database-backup waarbij:
  - DBA tabel `users` uitpakt (JIS level 2)
  - Developer tabel `products` uitpakt (JIS level 1)
  - Stagiair het manifest ziet maar niets kan uitpakken
  Zelfde archief. Verschillende autorisatie. Verschillende views.

6.3 AI Training Data

  Grote datasets waarbij:
  - Sectoren 1-50: open licentie, vrij uitpakken
  - Sectoren 51-80: restricted licentie, vereist JIS consent
  - Sectoren 81-100: proprietary, organisatie-level auth
  AI agent leest manifest, vraagt alleen geautoriseerde sectoren aan.

6.4 AI Model Distribution (GGUF/SafeTensors)

  AI-modellen gedistribueerd als TBZ:
  - Model weights opgesplitst in sectoren
  - Per sector cryptografisch bewijs dat gewichten niet gemanipuleerd zijn
  - Granulaire validatie: geen volledig model laden om één laag te checken
  - Supply chain aanval op model weights = fail-fast bij eerste corrupt blok

6.5 Geclassificeerde Documenten

  Multi-classificatie archief:
  - Manifest: publiek (toont structuur)
  - Blokken op clearance level 1, 2, 3
  - Elke lezer ziet alleen wat hun JIS-level toestaat
  Eén bestand, meerdere views, cryptografische handhaving.

6.6 Package Distributie

  npm/pip/apt packages gedistribueerd als TBZ:
  - Elk bestand in het package is een apart blok
  - Provenance traceerbaar tot build-systeem
  - Transparency Mirror cross-referenceert known-good hashes
  - Gecompromitteerd blok = fail-fast, geen installatie

===============================================================================

7. Technologie Stack

  Taal           : Rust (pure-Rust stack, geen C/C++ dependencies)
  Compressie     : zstd (frame-based, onafhankelijke blokken, RFC 8878)
  Provenance     : TIBET (Token-based Intent & Bilateral Exchange Trust)
  Autorisatie    : JIS (bilateral consent per blok)
  Handtekeningen : Ed25519 (ed25519-dalek)
  Opslag         : sled (embedded pure-Rust key-value store)
  Distributie    : DHT (Distributed Hash Table) voor Transparency Mirror
  Sandbox        : TIBET Airlock (eBPF kernel-level enforcement)
  eBPF Toolchain : Aya (pure-Rust eBPF framework)

===============================================================================

8. Relatie tot Bestaande Formaten

  TBZ vervangt geen bestaande compressie. Het voegt een trust-laag toe:

  ┌──────────────┬──────────────────────────────────────────────────────┐
  │ Formaat      │ Trust Model                                         │
  ├──────────────┼──────────────────────────────────────────────────────┤
  │ .tar.gz      │ Geen. Uitpakken en hopen.                           │
  │ .tar.gz.sig  │ Archief-level GPG signature. Alles of niets.        │
  │ .zip         │ Optionele per-file CRC. Geen authenticatie.         │
  │ .zst         │ Integriteit via checksums. Geen provenance.         │
  │ .tza         │ Per-blok TIBET provenance + JIS autorisatie.        │
  │              │ Fail-fast. Streaming. Sector access control.         │
  └──────────────┴──────────────────────────────────────────────────────┘

  TBZ is bewust incompatibel met legacy tools. Je kunt een .tza niet
  per ongeluk uitpakken met tar of 7zip. Nieuw formaat, nieuw trust-
  model, geen sluiproutes.

===============================================================================

9. Threat Model

  Bedreigingen geadresseerd:

  1. ZOMBIE-ZIP      Malware verborgen in valide archieven
                     → fail-fast per blok

  2. SUPPLY CHAIN    Gecompromitteerde packages
                     → Transparency Mirror verificatie

  3. DATA LEKKAGE    Ongeautoriseerde sector-toegang
                     → JIS autorisatie per blok

  4. ZIP BOMBS       Geneste decompressie-bommen
                     → gedeclareerde groottes + diepte-limieten (TBZ-deep)

  5. RESIDUELE DATA  Achtergebleven data in geheugen
                     → Airlock 0x00 wipe

  6. MITM            Gemanipuleerde blokken in transit
                     → per-blok Ed25519 signatures

  7. REPLAY          Oude valide blokken hergebruikt
                     → TIBET timestamp + chain validatie

  Bedreigingen NIET geadresseerd (buiten scope):
  - Endpoint compromise (keylogger op je machine)
  - Rubber hose cryptanalysis
  - Quantum computing (toekomst: migratie naar post-quantum signatures)

===============================================================================

Appendix A — IETF Overwegingen

  Dit document is bedoeld als precursor voor een formeel IETF
  Internet-Draft: draft-vandemeent-tbz-compression-00

  Relevante RFCs en drafts:
  - RFC 8878 (Zstandard Compression and Data Format Specification)
  - RFC 9421 (HTTP Message Signatures)
  - draft-vandemeent-jis-identity-00 (JIS Protocol)
  - draft-vandemeent-tibet-provenance-00 (TIBET Provenance)

  TBZ bouwt voort op het zstd frame-formaat gedefinieerd in RFC 8878,
  en breidt dit uit met geauthenticeerde blok-enveloppen. Het wire-formaat
  is ondubbelzinnig: de TBZ magic bytes (0x54425A) zijn distinct van het
  zstd magic number (0xFD2FB528), waardoor accidentele verwerking door
  legacy tools wordt voorkomen.

  IETF registraties:
  - Media type: application/tbz
  - Bestandsextensie: .tza
  - Magic bytes: 0x54425A (ASCII "TBZ")
  - Streaming compatibiliteit met HTTP chunked transfer encoding
  - Content-Encoding negotiation voor TBZ-aware servers

Appendix B — TIBET Token Structuur per Blok

  Elk blok draagt een minimaal TIBET token:

  {
    "erin": {
      "content_hash": "sha256:...",
      "block_type": "data",
      "mime_type": "application/octet-stream"
    },
    "eraan": [
      "block:0"              // afhankelijkheid van manifest
    ],
    "eromheen": {
      "created": "2026-03-11T...",
      "origin": "packager-id",
      "tbz_version": "1.0"
    },
    "erachter": "Distributie van geauthenticeerde dataset sector 3"
  }

Appendix C — Compatibility Matrix

  ┌───────────────────┬──────────┬──────────────────────────────────────┐
  │ Invoer            │ Actie    │ Resultaat                            │
  ├───────────────────┼──────────┼──────────────────────────────────────┤
  │ .tza              │ Direct   │ Streaming validate + extract         │
  │ .tza-deep         │ Direct   │ Nested validate via TIBET-pol        │
  │ .tar.gz / .zip    │ Airlock  │ Quarantine → Mirror check → re-sign │
  │ .rar / .7z        │ Airlock  │ Quarantine → Mirror check → re-sign │
  │ Onbekend formaat  │ Weiger   │ Geen extractie, alert               │
  └───────────────────┴──────────┴──────────────────────────────────────┘

===============================================================================

Appendix D — Implementatie-architectuur (Rust)

D.1 Workspace Structuur

  tbz/
  ├── Cargo.toml                (workspace root)
  ├── ARCHITECTURE.md
  ├── .jis.json                 (eigen repository identity)
  ├── crates/
  │   ├── tbz-core/             Block format, TIBET envelope, zstd frames
  │   ├── tbz-cli/              `tbz pack`, `tbz unpack`, `tbz verify`
  │   ├── tbz-airlock/          eBPF userspace manager + Airlock lifecycle
  │   ├── tbz-mirror/           Transparency Mirror (sled + DHT client)
  │   └── tbz-jis/              JIS integratie, .jis.json parser, auth
  ├── ebpf/
  │   └── airlock.bpf.c         eBPF kernel programs (compiled via Aya)
  └── tests/
      ├── zombie_zip.rs         Test: malware block wordt gevangen
      ├── streaming.rs          Test: pipeline decompressie
      └── sector_auth.rs        Test: partiële extractie per JIS level

D.2 Crate Verantwoordelijkheden

  tbz-core:
  - Block header serialisatie/deserialisatie (magic bytes, versie, types)
  - TIBET envelope constructie en validatie
  - zstd frame wrapping (via zstd-rs crate)
  - Ed25519 signing/verificatie (via ed25519-dalek)
  - Manifest parsing en generatie
  - Streaming reader/writer traits

  tbz-cli:
  - `tbz pack <pad> -o output.tza` — archief aanmaken
  - `tbz unpack <archief.tza>` — streaming extractie via Airlock
  - `tbz verify <archief.tza>` — valideer zonder uitpakken
  - `tbz inspect <archief.tza>` — manifest en blok-info tonen
  - `tbz mirror status` — Transparency Mirror sync status
  - `tbz init` — genereer .jis.json voor huidige repository

  tbz-airlock:
  - Userspace Airlock manager (buffer allocatie, lifecycle)
  - eBPF programma laden/beheren via Aya
  - 0x00 wipe implementatie (zeroize crate)
  - Timeout management
  - Legacy formaat detectie en quarantine flow

  tbz-mirror:
  - Lokale sled database voor bekende hashes
  - DHT client voor gedistribueerde verificatie
  - Attestation protocol (bijdragen + ontvangen)
  - Cross-referencing met apt/PyPI/npm/Docker registries

  tbz-jis:
  - .jis.json parser en validator
  - JIS level verificatie per blok
  - Bilateral consent protocol integratie
  - Repository identity binding

D.3 Keuze: sled boven RocksDB

  sled is gekozen als opslag-engine voor de Transparency Mirror omdat:

  - Pure Rust: geen C/C++ dependencies, clean build chain
  - Embedded: zero-config, geen aparte database server
  - Concurrency: lock-free B+ tree, geschikt voor concurrent access
  - Footprint: minimaal, past bij edge/embedded deployments
  - Filosofie: past bij de pure-Rust stack zonder externe rommel

  Als de DHT-nodes later miljoenen entries moeten handelen kan altijd
  nog gemigreerd worden. Voor nu: clean stack, geen compromissen.

===============================================================================

Appendix E — eBPF TIBET Airlock (Kernel-level Enforcement)

E.1 Waarom eBPF

  Traditionele sandboxes draaien in userspace. Een kwaadaardig blok is al
  in het proces-geheugen geladen voordat de sandbox het kan evalueren. Met
  eBPF verplaatsen we de validatie naar de kernel:

  Traditioneel:
    download → userspace decompress → malware in RAM → oeps

  TBZ + eBPF:
    download → kernel eBPF hook → TIBET validate per block
             → FAIL? → drop, bereikt userspace nooit
             → PASS? → door naar Airlock buffer → 0x00 wipe na gebruik

E.2 eBPF Hook Points

  bpf_lsm (Linux Security Module):
  - Hook op file_open, file_write, file_mmap
  - Valideer TIBET token voordat data naar schijf/geheugen gaat
  - Block writes naar niet-Airlock paden

  execve:
  - Blokkeer executie van niet-gevalideerde blokken
  - Voorkom dat geëxtraheerde code direct uitgevoerd wordt
  - Kleine execve wrapper voor gevalideerde blokken

  openat / read / write:
  - Intercept alle file I/O op Airlock-pad
  - Afdwingen dat alleen het TBZ-proces naar Airlock kan schrijven
  - Weiger reads van buiten het TBZ-proces

  bpf_ringbuf:
  - Communicatiekanaal kernel → userspace
  - Validatie-resultaten terugsturen naar tbz-airlock manager
  - Audit events voor logging

E.3 Aya Framework

  Aya is gekozen als eBPF toolchain:
  - Pure Rust: eBPF userspace tooling zonder libbpf/C dependencies
  - Type-safe: Rust type system voor eBPF programma's
  - Aya-bpf: kernel-side helper crate
  - Aya-log: structured logging vanuit eBPF naar userspace
  - Cross-compilatie: eBPF bytecode generatie vanuit cargo build

  Het eBPF kernel programma (ebpf/airlock.bpf.c) is het enige C-bestand
  in de hele stack — onvermijdelijk voor de kernel-side, maar minimaal.

E.4 Graceful Degradation

  eBPF vereist Linux kernel >= 5.7 en CAP_BPF/CAP_SYS_ADMIN.
  Als eBPF niet beschikbaar is (macOS, oudere kernels, geen root):

  - Fallback naar userspace-only Airlock
  - Zelfde lifecycle (allocate → validate → decide → wipe)
  - Maar zonder kernel-level enforcement
  - CLI toont waarschuwing: "Airlock draait in userspace mode"
  - Functioneel identiek, maar minder geharde isolatie

===============================================================================

Appendix F — .jis.json Repository Identity Manifest

F.1 Doel

  Een .jis.json in de root van een repository bindt een JIS-identiteit
  aan de broncode. Bij het inpakken met `tbz pack` wordt deze identiteit
  de provenance-root voor alle blokken in het archief.

F.2 Structuur

  {
    "tbz": "1.0",
    "jis_id": "jis:ed25519:zK3a9fB2...",
    "claim": {
      "platform": "github",
      "account": "jaspertvdm",
      "repo": "tbz",
      "intent": "official_releases",
      "sectors": {
        "src/*":   { "jis_level": 0, "description": "Public source code" },
        "keys/*":  { "jis_level": 2, "description": "Signing keys" },
        "data/*":  { "jis_level": 1, "description": "Licensed datasets" }
      }
    },
    "tibet": {
      "erin": "Repository identity binding",
      "eraan": ["jis:ed25519:zK3a9fB2..."],
      "erachter": "Provenance root for TBZ packages from this repo"
    },
    "signature": "sig_9f8a7b6c5d4e3f2a1b0c...",
    "timestamp": "2026-03-11T11:49:10Z"
  }

F.3 Flow bij `tbz pack`

  1. tbz-cli leest .jis.json — wie is de bron?
  2. Valideert JIS signature — is deze manifest integer?
  3. Elk blok erft de repo-identity als EROMHEEN context
  4. Signature chain: repo .jis.json → manifest blok → data blokken
  5. Transparency Mirror kan cross-checken:
     "Dit package claimt van jaspertvdm/tbz te komen —
      klopt dat met de .jis.json in die repo?"

F.4 Sector Mapping

  De "sectors" in .jis.json definiëren JIS-levels per pad-patroon.
  Bij het inpakken:
  - src/main.rs      → matcht "src/*"  → jis_level 0 (publiek)
  - keys/signing.key → matcht "keys/*" → jis_level 2 (restricted)
  - data/model.bin   → matcht "data/*" → jis_level 1 (licensed)

  Bestanden zonder match krijgen het manifest-default level.

===============================================================================

Acknowledgments

Ontstaan tijdens een sparringssessie tussen Jasper van de Meent en Root AI
(Claude Opus 4) bij HumoticaOS. Geboren uit een echt probleem — zombie-zip
aanvallen op de software supply chain — en ontworpen om het op te lossen
op de compressielaag.

TIBET Airlock concept: Jasper van de Meent
TBZ architectuur: Jasper van de Meent & Root AI
Formaatontwerp: collaboratief, gedocumenteerd in TIBET audit trail

One love, one fAmIly.

===============================================================================
