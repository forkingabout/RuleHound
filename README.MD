# WE NEED YOU 🫵 

This is an attempt to make a half decent firewall analysis tool. But there are too many bloody firewalls. If you make an auditmodule or any auditfiles, or even better if you want to add new features, please contribute! Also this project is far from immaculate. You have been warned. If you chuck claude this repo auditfiles are easy to vibe code. You just need to double check it. If you perfect an auditmodule, please contribute it! You can even drop them via email to `forkingabout@atomicmail.io` if need be.

# What Is RuleHound

RuleHound is a graph based firewall security analysis tool using neo4j \(it's bloodhound but for firewalls\). The rulehound binary runs a web server with an APIs to ingest collector output, clear the db, etc. The rulehoundcli binary enables some simple db interactions, including querying it \(as long as the query returns a single string\), and using auditfiles to audit configurations loaded in there. There is also a feature to analyse a firewall config but at the minute this has only been confirmed to work for SonicWall NSA 2700 exp files. There is a web interface so you can view the loaded neo4j config representation and make graph queries.

> TLDR: To audit a config you start the server, ingest the config \(assuming a collector and auditfiles already exist for your firewall\), and use rulehoundcli to run the auditfile against it.

There are some formats and APIs to be familiar with. Most are yaml schemas:
**Formats:**
- Collector output format: Simple YAML based format to describe nodes and relationships. 
- Auditfile format: A bit more complicated format to describe findings, queries to validate them, finding texts, severities, etc.
**APIs:**
- HTTP Ingestion: POST to `/api/ingest/yaml` with body of collector output format. MUST have `Content-Type: application/yaml; charset=utf-8`.
- HTTP DB Clear: POST to `/api/clear` clears neo4j db.
- HTTP Query: POST to `/api/query` or `/api/query/json` for neo4j DB queries. 

# Features & Capabilities \(atm\)

## Web Interface

- Ingest collector output
- Clear db
- Render neo4j representations of configs
- Make cypher queries and view results

## CLI

- Connect to DB
- Make cypher queries **as long as they return a single string** and pretty print.
- Read auditfiles to audit config loaded in db and produce html, csv, md, json, and yaml reports
- Analyse fw config files and attempt to pretty print versioning info.  

# TO DO / Unfinished Features

- CLI fw config analyser only can detect SonicWall .exp and has only been tested against NSA 2700.
- CLI can only connect to db with host / port specified or config file. -docker-init has not been finished but intends to spin up fresh neo4j with the docker-compose and connect to it.
- The only auditmodule is `sonicwall\/NSA 2700` and is a bit half done. Collector does its best to mirror config and map relationships, but not all values / masks have been reverse engineered. Auditfiles aren't 100% correct and produce some false positives. That being said, it works.
- Auditfiles have KnownCompatability and KnownIncompatability fields in the yaml. I want to add a search feature which uses these string lists so it can search for audit modules which support a given firewall model.
- Can't clear the db from CLI but that will be easy to add.
- Error handling and reporting is not centralised / uniform. We ideally want a single function from core to be used, and we want functions that may collect many errors \(such as those responsible for parsing auditfiles or collector output\) to not print a single error and kill the proc. They should collect all error messages and output all before exit.
- Would like to make it so you can eventually do everything with the web interface without the cli but more bothered about sorting out everything else. But if your good with web any help would be greatly appreciated.

# Usage Guide

## Quickstart

> These are bash commands. PowerShell commands are pretty much the same substituting file system path '/' for '\'. 

**Prerequisites:**
- Install Docker 

Start neo4j container, build binaries, and start RuleHound:
```
docker-compose up
go build cmd/rulehound
go build cmd/rulehoundcli
./rulehound
```
> The RuleHound binary uses the config file at `config/RuleHound.yaml` by default. To use a different config file path use `-config-file`.

Run a collector to generate the collector output YAML. For example:
```
'./auditmodules/sonicwall/NSA 2700/collector/collector-NSA-2700.py' -o ./sonicwall-collector-output.yaml ./sonicwall-export.exp
```
Ingest the output into RuleHound with the CLI:
```
./rulehoundcli -web-host localhost -web-port 8080 -ingest-yaml ./sonicwall-collector-output.yaml
```
Run an auditfile on the ingested config and output a HTML report:
```
./rulehoundcli -db-host localhost -db-port 7687 -report './auditmodule/sonicwall/NSA 2700/auditfiles/NSA 2700 v1.yaml' -report-html ./sonicwall-report.html
```

> Can't find a collector for your firewall? Chuck this repo or at least an existing collector and matching audifile + the files in `db/` and `reporter/` and this readme to Claude and ask it to create a collector and auditfile for firewall x. Ask for the collector to mirror the config's real values and never invent values / placeholders, and to add the relationships by these values. If there is an existing open source parser for your firewall config then give it the source code for inspiration, or if there are docs describing the objects in the config give it that. After that I recommend you use them to gen a report, examine the queries made and their values for each finding and use your human brain to determine false positives and have a back and fourth with Claude to determine the most accurate queries for the finding. If you perfect an auditmodule please contribute it! You can even drop them by email to `forkingabout@atomicmail.io` if need be. 

## Auditmodules

Auditmodules are organised as follows within `auditmodules/`:
```
firewall-brand/
|
+-- auditmodule-name/ 
|         |
|         +-- auditfiles/
|         |       |
|         |       +-- auditfile-generic-v1.yaml
|         |       |
|         |       +-- auditfile-CIS-v1.yaml
|         |
|         +-- collector/
|                 |
|                 +-- collector-executable 
|                 |
|                 +-- meta.yaml 
```

- There can be mulitple auditfiles but only a single collector within an auditmodule. 
- Auditfiles contain KnownCompatability and KnownIncompatability fields within Meta so you can add any firewall versions / models / builds which cannot be represented accuratley with the collector.
- The meta.yaml within the `collector/` dir also contains KnownCompatability and KnownIncompatability fields for the same reason.
- Auditfiles have a Version field in Meta so if you create a new audit file you can increment the version. To be helpful, prepend `-vx` to the auditfile name where `x` is the version number.
- You may create different auditfiles which make different checks against different benchmarks, but if you make a new collector it's best to have a generic auditfile to use.
- If you create a new collector for a certain brand / version of firewall, and a collector for that brand / version of firewall already exists, just add your author name or something else to differentiate between the two.

> A collector can create any arbitrary objects. The trust model with auditfiles and a single collector in a single auditmodule is that those auditfiles will definitley work for the neo4j firewall config representation object model that the collector produces. Using that auditmodule on any other collector should not be trusted to produce reliable audit results or reports. 

## Ingestion

You can either use the CLI with `rulehound` binary running:
```
./rulehoundcli -web-host localhost -web-port 8080 -ingest-yaml ./sonicwall-collector-output.yaml
```
or you can use the web interface with the upload button in top left.



# Big Ups

- Man like @S1lly-G1t for being a helpful firewall veteran
