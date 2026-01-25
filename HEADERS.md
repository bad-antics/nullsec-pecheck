# PE File Headers Analysis Guide

## Overview
Portable Executable file format analysis for malware detection.

## DOS Header
- e_magic: MZ signature
- e_lfanew: PE offset
- DOS stub analysis

## PE Headers

### File Header
- Machine type
- Number of sections
- TimeDateStamp
- Characteristics

### Optional Header
- Magic (32/64-bit)
- Entry point
- Image base
- Section alignment
- Subsystem

## Section Analysis

### Common Sections
- .text: Code
- .data: Initialized data
- .rdata: Read-only data
- .rsrc: Resources
- .reloc: Relocations

### Suspicious Indicators
- Unusual section names
- High entropy sections
- Executable .data
- Overlapping sections

## Import/Export Tables

### Import Analysis
- API categorization
- Suspicious imports
- Anti-analysis APIs
- Network functions

### Export Analysis
- Function names
- Ordinals
- Forwarded exports

## Malware Indicators
- Packer signatures
- Missing imports
- Abnormal timestamps
- Resource anomalies

## Legal Notice
For authorized malware analysis.
