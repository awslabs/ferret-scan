# Ferret Scan vs. Competitors Battle Card

[← Back to Documentation Index](README.md)

## Executive Summary

Ferret Scan is a comprehensive, **local-first** sensitive data detection tool that provides enterprise-grade security without the cloud dependency, cost, and privacy concerns of cloud-based solutions.

## Competitive Landscape

| Feature | **Ferret Scan** | Amazon Comprehend PII | Matilda Sanitizer |
|---------|-----------------|----------------------|-------------------|
| **Deployment** | ✅ Local/On-premisesᵀ | ❌ Cloud-only | ❌ Internal AWS only |
| **Data Privacy** | ✅ No data leaves premisesᵀ | ❌ Data sent to AWS | ❌ Data processed in cloud |
| **Cost Model** | ✅ **FREE** | ❌ Pay-per-use (~$0.0001/100 chars) | ❌ Internal allocation |
| **Offline Capability** | ✅ Works without Internetᵀ | ❌ Requires internet | ❌ Requires AWS connectivity |
| **Metadata Extraction** | ✅ Office Docs, PDF, Images | ❌ Not supported | ❌ Not supported |
| **Embedded Media** | ✅ Office Docs, PDF, Images | ❌ Not supported | ❌ Not supported |
| **File Format Support** | ✅ 50+ formats (PDF, Office, images, audio) | ❌ Text only | 🔶 Limited formats |
| **Custom Validators** | ✅ Pluggable architecture | ❌ Fixed ML models | ❌ Policy-based only |
| **Suppression System** | ✅ Advanced rule management | ❌ No suppression | 🔶 Basic policy rules |
| **Web UI** | ✅ Full-featured interface | ✅ AWS Console | 🔶 Limited interface |
| **Docker Support** | ✅ Containerized deployment | ❌ Cloud service only | ❌ Internal infrastructure |
| **CI/CD Integration** | ✅ Pre-commit hooks, pipelines | 🔶 API integration only | 🔶 Limited integration |
| **Compliance** | ✅ Data residency compliantᵀ | ❌ Subject to AWS terms | ❌ Internal use only |

ᵀ By default, if optional AWS services are not used.

## Key Differentiators

### 🔒 **Privacy & Security First**
- **Ferret Scan**: All processing happens locally, sensitive data never leaves your environment
- **Comprehend**: Sends your sensitive data to AWS for processing
- **Matilda**: Internal AWS tool, data processed in Amazon's infrastructure

### 💰 **Zero Costs**
- **Ferret Scan**: Completely FREE, no usage fees
- **Comprehend**: $0.0001 per 100 characters (can be expensive for large datasets)
- **Matilda**: Internal cost allocation, not available externally

### 🚀 **Comprehensive Detection with Enhanced Accuracy**
- **Ferret Scan**: 9 enhanced validators with zero-confidence filtering + advanced false positive prevention + AI integration when needed
- **Comprehend**: ML-based PII detection only
- **Matilda**: Policy-based sanitization, limited detection types

### 🔧 **DevOps Ready**
- **Ferret Scan**: Docker containers, pre-commit hooks, CI/CD pipeline integration
- **Comprehend**: API calls only, requires custom integration
- **Matilda**: Internal AWS tooling, limited external integration

### 📁 **Multi-Format Support**
- **Ferret Scan**: PDFs, Office docs, images (OCR), audio (transcription), source code
- **Comprehend**: Plain text only
- **Matilda**: Limited to text-based formats

## Technical Advantages

### Advanced Architecture
```
Ferret Scan: Modular validators + Pluggable preprocessors + Memory security
Comprehend: Black-box ML model
Matilda: Policy engine + Basic sanitization
```

### Detection Capabilities
| Data Type | Ferret Scan | Comprehend | Matilda |
|-----------|-------------|------------|---------|
| Credit Cards | ✅ Vendor validation + Luhn | 🔶 Generic detection | 🔶 Pattern-based |
| Passports | ✅ Multi-country formats | 🔶 Limited coverage | 🔶 Basic patterns |
| SSN | ✅ Multiple formats | ✅ Multiple formats | 🔶 Pattern-based |
| Secrets/API Keys | ✅ Entropy analysis | ❌ Not supported | ❌ Not supported |
| IP (Patents/Trademarks) | ✅ Specialized detection | ❌ Not supported | ❌ Not supported |
| Custom Types | ✅ Easy to add | ❌ Not possible | 🔶 Policy-dependent |

## Use Case Scenarios

### ✅ **Choose Ferret Scan When:**
- Data must remain on-premises (compliance, security)
- Processing large volumes regularly (cost-effective)
- Need comprehensive file format support
- Require custom detection types
- Want zero-cost solution
- Need offline capability
- Require advanced suppression management
- Want seamless DevOps integration (Docker, pre-commit, CI/CD)

### ❌ **Comprehend/Matilda Limitations:**
- **Comprehend**: Expensive for large datasets, cloud dependency, limited formats
- **Matilda**: Internal AWS only, not available for external customers

## ROI Analysis

### Cost Comparison (1TB of text data/month)
- **Ferret Scan**: **$0 (FREE)**
- **Comprehend**: ~$10,000/month ($0.0001 × 10B characters)
- **Matilda**: Not available for purchase

### ROI: **Immediate savings** from day one

## Objection Handling

**"We already use AWS services"**
- Ferret Scan integrates with AWS when needed (optional GenAI features)
- Provides local processing for sensitive data, cloud for enhancement

**"Comprehend has better ML accuracy"**
- Ferret Scan is FREE with rule-based precision plus optional ML enhancement
- Lower false positive rates through advanced validation and suppression

**"What about Matilda?"**
- Matilda is internal AWS tooling, not available for customer use
- Ferret Scan provides similar capabilities with better file format support

## Competitive Positioning

### **Ferret Scan = "Secure, Comprehensive, FREE"**
- **vs Comprehend**: "Keep your data secure and eliminate costs entirely"
- **vs Matilda**: "Get enterprise-grade detection for free without AWS dependency"
