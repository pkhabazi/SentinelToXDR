---
layout: Conceptual
title: Compare Microsoft Sentinel analytics rules and Microsoft Defender custom detections - Microsoft Security | Microsoft Learn
canonicalUrl: https://learn.microsoft.com/en-us/azure/sentinel/compare-analytics-rules-custom-detections
breadcrumb_path: breadcrumb/toc.json
feedback_help_link_url: https://learn.microsoft.com/answers/tags/423/microsoft-sentinel/
feedback_help_link_type: get-help-at-qna
feedback_product_url: https://feedback.azure.com/d365community/forum/79b1327d-d925-ec11-b6e6-000d3a4f06a4
feedback_system: Standard
learn_banner_products:
- azure
permissioned-type: public
recommendations: true
recommendation_types:
- Training
- Certification
uhfHeaderId: azure
ms.suite: office
adobe-target: true
manager: orspodek
ms.service: microsoft-sentinel
ms.subservice: sentinel-siem
search.appverid: met150
description: Compare the different features supported by Microsoft Sentinel analytics rules and Microsoft Defender custom detections.
ms.author: pauloliveria
author: poliveria
ms.reviewer: nonutkev
ms.topic: product-comparison
ms.date: 2026-05-19T00:00:00.0000000Z
ms.collection: ms-security
locale: en-us
document_id: e077c24d-c9ad-2350-c27c-0ca841d756bc
document_version_independent_id: a2c87e85-8daa-bb87-ecbb-87e92b0c29f8
updated_at: 2026-05-19T07:34:00.0000000Z
original_content_git_url: https://github.com/MicrosoftDocs/defender-docs-pr/blob/live/sentinel/compare-analytics-rules-custom-detections.md
gitcommit: https://github.com/MicrosoftDocs/defender-docs-pr/blob/5c6b247409b0a426e2a24485684a6bcd0a14cf05/sentinel/compare-analytics-rules-custom-detections.md
git_commit_id: 5c6b247409b0a426e2a24485684a6bcd0a14cf05
site_name: Docs
depot_name: Azure.sentinel-azure
page_type: conceptual
toc_rel: toc.json
word_count: 580
asset_id: sentinel/compare-analytics-rules-custom-detections
moniker_range_name:
monikers: []
item_type: Content
source_path: sentinel/compare-analytics-rules-custom-detections.md
cmProducts:
- https://authoring-docs-microsoft.poolparty.biz/devrel/8a94907f-2511-4271-b5ca-ec7f2e75067c
- https://microsoft-devrel.poolparty.biz/DevRelOfferingOntology/c671beaa-a830-4c9f-aceb-97379ee031ca
spProducts:
- https://authoring-docs-microsoft.poolparty.biz/devrel/bffa8e88-f633-409d-a24d-083bdbc68872
- https://microsoft-devrel.poolparty.biz/DevRelOfferingOntology/8921374c-4dbe-4ed0-b011-a39e18bfbd98
platformId: 696a73b8-dda0-ecdd-7f4f-90221bed1c72
---

> **Source and licence.** This is a copy of the Microsoft Learn article
> [Compare Microsoft Sentinel analytics rules and Microsoft Defender custom detections](https://learn.microsoft.com/en-us/azure/sentinel/compare-analytics-rules-custom-detections),
> kept here so the lookup tables in `src/Data/*.psd1` can be traced to the exact revision they
> were derived from (see the `git_commit_id` in the front matter). The content is (c) Microsoft
> and licensed under [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/). Read the live
> page for the current state.

# Compare Microsoft Sentinel analytics rules and Microsoft Defender custom detections - Microsoft Security | Microsoft Learn

This article lists and compares the different features supported by Microsoft Sentinel [analytics rules](threat-detection) and Microsoft Defender [custom detections](/en-us/defender-xdr/custom-detections-overview?toc=/azure/sentinel/TOC.json&amp;bc=/azure/sentinel/breadcrumb/toc.json). It also provides additional information, such as plans to support any analytics rules capabilities that aren't available in custom detections, if applicable.

Important

**Custom detections** is now the best way to create new rules across Microsoft Sentinel SIEM Microsoft Defender XDR. With custom detections, you can reduce ingestion costs, get unlimited real-time detections, and benefit from seamless integration with Defender XDR data, functions, and remediation actions with automatic entity mapping. For more information, read [this blog](https://techcommunity.microsoft.com/blog/microsoftthreatprotectionblog/custom-detections-are-now-the-unified-experience-for-creating-detections-in-micr/4463875).

## Compare analytics rules and custom detections features

| **Feature** | **Capability** | **Analytics rules** | **Custom detections** |
| --- | --- | --- | --- |
| **Alert enrichment** | Flexible entity mapping over Sentinel data | Supported | Supported |
|  | Reflect custom detections in [MITRE ATT&CK page](/en-us/azure/sentinel/mitre-coverage?tabs=defender-portal) | Supported | Planned |
|  | Link multiple MITRE tactics | Supported | Planned |
|  | Support full list of MITRE techniques and subtechniques | Supported | Planned |
|  | Enrich alerts with custom details | Supported | Supported |
|  | Define alert title and description dynamically - Integrate query results in runtime | Supported | Supported |
|  | Define all alerts properties dynamically - Integrate query results in runtime | Supported | Planned |
| **Rule frequency** | Support flexible and high frequency for Sentinel data | Supported | Supported |
|  | Near-real-time (NRT) rules on Sentinel data | Supported | [Supported](/en-us/defender-xdr/custom-detection-rules#queries-you-can-run-continuously) |
|  | NRT streaming technology - Test events as they stream, not sensitive to ingestion delays | Not supported. Analytics NRT rules test events after they're ingested. | Supported |
|  | Determine rule's first run | Supported | Not supported |
| **Rule lookback** | Lookback support | Lookback is flexible:<br>- Up to 48 hours for frequency higher than one hour<br>- Up to 14 days for frequency of one hour and less | [In public preview](/en-us/defender-xdr/custom-detection-rules#lookback). Parity with analytics rules on Sentinel data. |
| **Rule data** | Defender XDR data | Not supported | Supported |
|  | Sentinel analytics tier | Supported | Supported |
| **Automated actions** | Native Defender XDR remediation actions | Not supported | Supported |
|  | Sentinel automation rules with incident trigger | Supported | Planned |
|  | Sentinel automation rules with alert trigger | Supported | Planned |
| **Audit and health visibility** | Rules audit logs available in advanced hunting | Supported (in the `SentinelAudit` table) | Exposed in the `CloudAppEvents` table for Microsoft Defender for Cloud Apps users.This capability will be available for all custom detections users in the future. |
|  | Rules health logs available in advanced hunting | Supported (in the `SentinelHealth` table) | Planned |
| **Control alerts and events grouping** | Customize alert grouping logic | Supported | Not supported. In the SIEM and XDR solutions, the correlation engine takes care of the alerts' grouping logic and can address the need to configure the grouping logic. |
|  | Choose between all events under one alert and one alert per event | Supported | Not supported |
|  | Group events to one alert when custom details, alert dynamic details, and entities are identical | Not supported | Supported |
| **Control incidents and alerts creation** | Exclude incidents from correlation engine - Ensure that incidents from different rules remain separated | Planned | Planned |
|  | Create alerts without incidents | Supported | Not supported |
|  | Alerts suppression - Define alert suppression after the rule runs | Supported | Not supported |
| **Rules management** | Rerun rule on demand on a previous time window | Supported | Planned |
|  | Run rule on demand | Not supported | Supported |
|  | Health and quality workbooks | Supported | Planned |
|  | Integration with Sentinel repositories | Supported | Planned |
|  | Manage rules from API | Supported | Supported |
|  | Bicep support | Supported | Planned |
| **Content hub** | Create rules from content hub | Supported | Planned |
| **Multi workspace** | Create custom detections on any workspaces onboarded to Defender | Supported | Planned |
|  | Cross workspaces detection using the workspace operator | Supported | Planned |
| **Testing and validations** | Rule simulation from the rule's wizard | Supported | Planned |
