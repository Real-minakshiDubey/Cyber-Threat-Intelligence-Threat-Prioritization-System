# Cyber Threat Intelligence – Threat Prioritization System

## Overview
This project builds a simple Python-based threat prioritization system using the MITRE ATT&CK dataset. 
The system analyzes attack techniques and assigns risk scores based on logical keyword analysis 
to help security analysts prioritize high-risk threats.

## Dataset
Dataset used:
https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json

The dataset contains multiple cybersecurity objects including malware, tools, campaigns, 
and attack techniques. This project extracts only objects where:
type == "attack-pattern"

## Threat Scoring Logic
Each technique starts with a base score of 5.

Additional score is added based on:

### Name-Based Intelligence
- credential → +3
- execution → +2
- privilege → +3
- persistence → +2
- lateral → +2

### Description-Based Intelligence
- administrator → +2
- remote → +2
- bypass → +2
- stealth → +1

Techniques are then ranked from highest to lowest score.

## Results
The system outputs:
- Top 10 highest-risk techniques
- Critical threats where score ≥ 8.9

## How to Run
1. Install Python
2. Install requests library
3. Run the notebook
4. Execute all cells

## Why This Helps Analysts
This scoring system automates threat prioritization by highlighting techniques 
associated with credential theft, privilege escalation, remote exploitation, 
and security bypass behavior. It reduces manual workload and helps analysts 
focus on high-impact threats first.
