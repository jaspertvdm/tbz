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

Het .tbz (TIBET-zip) formaat is geen nieuw compressie-algoritme, maar een
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
    veilig .tbz formaat, getekend met de JIS-identiteit van de lokale sandbox.
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

  Compressie     : zstd (frame-based, onafhankelijke blokken, RFC 8878)
  Provenance     : TIBET (Token-based Intent & Bilateral Exchange Trust)
  Autorisatie    : JIS (bilateral consent per blok)
  Handtekeningen : Ed25519
  Distributie    : DHT (Distributed Hash Table) voor Transparency Mirror
  Sandbox        : TIBET Airlock (zero-residue quarantine buffer)

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
  │ .tbz         │ Per-blok TIBET provenance + JIS autorisatie.        │
  │              │ Fail-fast. Streaming. Sector access control.         │
  └──────────────┴──────────────────────────────────────────────────────┘

  TBZ is bewust incompatibel met legacy tools. Je kunt een .tbz niet
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
  - Bestandsextensie: .tbz
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
  │ .tbz              │ Direct   │ Streaming validate + extract         │
  │ .tbz-deep         │ Direct   │ Nested validate via TIBET-pol        │
  │ .tar.gz / .zip    │ Airlock  │ Quarantine → Mirror check → re-sign │
  │ .rar / .7z        │ Airlock  │ Quarantine → Mirror check → re-sign │
  │ Onbekend formaat  │ Weiger   │ Geen extractie, alert               │
  └───────────────────┴──────────┴──────────────────────────────────────┘

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
