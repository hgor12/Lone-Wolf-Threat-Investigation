# Lone-Wolf-Threat-Investigation
An individual forensic investigation of a suspect's laptop in a simulated threat case. I analyzed a disk image and a memory capture to reconstruct the suspect's activity, and found evidence in memory that was not present anywhere on disk.

**Scenario**

> Lone Wolf scenario from [Digital Corpora](https://digitalcorpora.org/corpora/scenarios/2018-lone-wolf-scenario/)

Jim Cloudy, increasingly radicalized by gun-control coverage, plans a lone-wolf attack and stores his writings across several cloud accounts. After his brother Paul finds the plans in shared documents and alerts police, a search warrant recovers Jim's laptop in Manhattan.

**Scope**: Determine whether Jim was planning a mass shooting, identify digital evidence of his intent, state of mind and escape plan, and determine whether cloud storage information was shared with Paul. Only the laptop's drive, memory dump and pagefile were analyzed.

### Evidence

| Item | Details |
|---|---|
| Laptop | Dell Latitude E7470 (S/N 8X4XYF2) |
| Drive | Samsung SSD 850 Pro 512 GB (S/N S1SANYAF500312A) |
| Disk image | Physical image, 9 EnCase (E01) segments, acquired with FTK Imager 3.1.1.8 on April 6, 2018 |
| Memory | `memdump.mem` |
| Pagefile | `pagefile.sys` |

The evidence files are not included in this repo.

### Tools Used

| Tool | Version | Used for |
|---|---|---|
| FTK Imager | 3.1.2.0 | Image verification |
| Autopsy | 4.22.1 | Primary disk analysis: artifacts, email, file metadata, timestamps |
| AccessData Registry Viewer | 2.0.0.7 | Registry hive analysis |
| Volatility 3 Framework | 2.28.1 | Memory analysis |
| Python (pandas, openpyxl) | 3.10.6 | Browser history conversion and categorization |
| macOS Terminal (`strings`, `grep`, `sed`) | — | Searching and cleaning text extracted from memory |

---

## Step 1 — Verify Evidence Integrity

I loaded the E01 image into FTK Imager and computed MD5 and SHA-1 hashes. The computed MD5 matched the MD5 recorded in the original acquisition log, and no bad blocks were found, confirming the image had not been altered or corrupted.

No acquisition hashes were provided for the memory dump or pagefile, so I computed baseline hashes before analysis.

| File | MD5 | SHA-1 |
|---|---|---|
| E01 image (9 segments) | `7af48fa65519e84246b1729e5b68f140` | `694e26624d1ea029eb50d793b198edf85be4b4fc` |
| `memdump.mem` | `694d1b7c761b50ff5145e0fed4f4f411` | `072d118d528d6f17772ef3e5042a0c37906defc9` |
| `pagefile.sys` | `f2299691fc75e667c12998eac2d2ca8c` | `e4c94667e0d013d6237aa281c08819ad8e03ed05` |

---

## Evidence Handling

All evidence was documented on standard forms before and during analysis.

- [Chain of Evidence](forms/Chain_of_Evidence.pdf): transfer of each item from the seizing detective to the examiner
- [Evidence Inventory](forms/Evidence_Inventory.pdf): description, serial number and custodian for each item
- [Incident Response Log](forms/Incident_Response_Log.pdf): dated record of each step of the examination

---

## Step 2 — Reconstruct the System Profile

Using Autopsy and Registry Viewer, I reconstructed the system profile from the registry hives.

| Item | Finding | Source |
|---|---|---|
| Computer name | DESKTOP-PM6C56D | `SYSTEM\ControlSet001\Control\ComputerName` |
| Registered owner | "Windows User" (no organization set) | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` |
| Operating system | Windows 10 Education | `SOFTWARE\Microsoft\Windows NT\CurrentVersion` |
| Device / sector size | 512,110,190,592 bytes / 512 bytes | Autopsy image properties |
| Disk structure | 6 allocated volumes; Volume 7 is the primary NTFS partition with user data | Autopsy file system details |
| Primary user | `jcloudy` (RID 1001, key `000003E9`) | `SAM\Domains\Account\Users` |
| Password hint | "It's me you idiot!" | `SAM\Domains\Account\Users\000003E9` |
| Time zone | Eastern Standard Time | `SYSTEM\ControlSet001\Control\TimeZoneInformation` |
| Last shutdown | 2018-03-27 21:45:28 UTC | `SYSTEM\ControlSet001\Control\Windows\ShutdownTime` |

### USB Device History

Two SanDisk Extreme USB drives were connected, found in `SYSTEM\ControlSet001\Enum\USBSTOR`.

| Device | Serial Number | Connected |
|---|---|---|
| USB #1 | AA0102151703553101594 | 2018-03-27 12:11:44 |
| USB #2 | AA0106031607074702215 | 2018-03-27 09:22:21 GMT |

---

## Step 3 — Cloud Accounts and Storage

The subject used at least four cloud storage services: **Google Drive, OneDrive, Dropbox and Box**. This was supported by local sync folders in the `jcloudy` profile and by Chrome saved logins recording accounts for Dropbox, Box, Twitter and Microsoft Live.

Key documents, including *The Cloudy Manifesto.docx* and *Operation 2nd Hand Smoke.pptx*, appeared across multiple cloud services, consistent with the subject's journal entry about preserving his writings in several places.

A file named *Brother chat.gdoc* was found in the Google Drive folder and in the Google Drive `cloud_graph.db` database, showing a document shared with Paul.

---

## Step 4 — Memory Analysis

Memory analysis was done in Volatility 3 and macOS Terminal. Full commands are in [`memory_analysis_steps.pdf`](memory_analysis_steps.pdf).

### Image information and running processes

```bash
python3 vol.py -f memdump.mem windows.info
python3 vol.py -f memdump.mem windows.psscan
```

`windows.info` confirmed a Windows 10 64-bit image captured at 2018-04-06 12:42:32. `windows.psscan` showed Chrome, Google Drive, Excel and Dropbox still running at capture, and **S3 Browser** (`S3browser-win3`) running from 2018-04-05 02:23:51 to 02:32:08 UTC.

### AWS account

AWS access keys follow the pattern `AKIA` + 16 characters, so I extracted every match from memory and counted how often each appeared, since the most frequent key would be the most significant.

```bash
strings memdump.mem | grep -oE 'AKIA[A-Z0-9]{16}' | sort | uniq -c | sort -rn
```

Searching the text around the most frequent key identified the account name (`jimcloudy1`) and region (`us-east-2`). The matching access and secret keys were also found on disk in `rootkey.csv` in the subject's Downloads folder.

### Email reconstruction

Searching memory for the subject's email address and his brother's name uncovered Gmail thread fragments (`gmail_quote`, `mailto:` links). Because whole email chains were repeated throughout memory, I extracted the surrounding text, stripped the HTML, decoded HTML entities, removed duplicates and sorted the messages by date to reconstruct the thread.

```bash
strings -n 10 memdump.mem | grep -E -A40 -B10 "On .* at .* wrote:|gmail_quote|@gmail.com" > raw_email_threads.txt
sed -E 's/<[^>]+>//g' raw_email_threads.txt > stripped_email_threads.txt
```

The reconstructed thread (March 29 – April 4, 2018) shows a debate over gun control in which Jim says "something drastic" would be needed to be heard, mentions traveling outside the country, and moves their conversation to a private Google document over fears of government surveillance.

### Credentials

I filtered text extracted from memory for platform names (Twitter, Box, Dropbox, Outlook, Live) alongside the subject's username, then searched those lines for credential keywords. This recovered full login credentials for the subject's **Dropbox** and **Box** accounts. Credential values are redacted here.

### Pagefile

I extracted readable text from `pagefile.sys` and searched for the subject's username. No significant information was recovered.

---

## Step 5 — Browser History Timeline

Chrome's omnibox (the address and search bar) stores every search and URL typed into it in a `Shortcuts` database. I exported it from Autopsy and used a Python script to convert the Chrome timestamps to Eastern Daylight Time and categorize each entry by keyword.

The cleaned dataset contains **103 entries** in seven categories: Weapon Research, Target Research, Escape Planning, Cloud Storage, Ideology, Counter-Surveillance and Weather.

From March 27 to April 6, 2018, the history shows a clear progression from **weapon research** (specific firearm models and ways to acquire them illegally), to **target reconnaissance** (gun-free zones, police response times, the venue and nearby locations), to **escape planning** (non-extradition countries, flights to Bali and moving cash through airport security).

---

## Step 6 — Key Evidence

### Documents

| Document | Last Modified (EDT) | Contents |
|---|---|---|
| The Cloudy Manifesto.docx | 2018-04-01 21:35:27 | Anti-gun-control views and explicit statements of intent |
| AIRPORT INFORMATION.docx | 2018-04-04 00:59:32 | Flight options and departure records; references the Fairfax County Democratic Committee |
| Operation 2nd Hand Smoke.pptx | 2018-04-04 01:11:27 | Venue reconnaissance, flight timing and Bali accommodation |
| Planning.docx | 2018-04-04 01:30:41 | Target preferences, supplies and escape route |
| Cloudy thoughts (4apr).docx | 2018-04-04 22:39:30 | Journal entry about the plan, the flight and preserving his writings in the cloud |

### Images

Ten screenshots and one deleted image document target reconnaissance and escape planning between March 29 and April 4, 2018, including:

- The Town Hall For Our Lives event page (April 7, 2018, Sterling, VA)
- Google Street View of the Cascades Library venue
- Driving directions between the venue and Dulles International Airport
- A round-trip flight booking from Washington Dulles to Denpasar, Bali, departing April 7
- A photo of the Democratic National Committee headquarters, deleted on April 6

---

## Findings

- The subject was planning a mass shooting at the Town Hall For Our Lives event on April 7, 2018, at the Cascades Library in Virginia.
- Documents, browser history and screenshots show a deliberate progression from weapon research to target reconnaissance to escape planning over the 11 days before the event.
- His escape plan was to drive to Dulles International Airport and fly to Bali on the day of the attack.
- He researched additional Democratic Party locations as possible targets.
- He kept his documents across at least four cloud platforms and shared a document with his brother after moving their conversation off email.
- Memory analysis recovered email correspondence and account credentials that were not present on the disk image.

---

## Reflection

This case had taught me how much evidence only exists in memory. The email thread between Jim and Paul and the Dropbox and Box passwords were not present on the disk image at all. Recovering them required working with raw text extracted from the memory dump, which was disorganized and contained many repeated email fragments. I developed a series of `strings`, `grep` and `sed` commands to clean that data into a readable timeline sorted by date, and this process proved to be as important as the search itself.

I also learned that patterns in the data can guide an investigation. Counting how often each AWS key appeared in memory identified the most significant one. Sorting 103 browser entries into categories revealed how the subject's planning progressed, which was difficult to see in the raw history.

## Files

- `Lone_Wolf_Forensic_Report.pdf` — full investigation report
- `memory_analysis_steps.pdf` — Volatility 3 and Terminal commands used for memory analysis
- `forms/` — chain of evidence, evidence inventory and incident response log
