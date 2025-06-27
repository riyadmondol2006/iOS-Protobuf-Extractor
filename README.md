# iOS Protobuf Extractor

Youtube video-
https://youtu.be/UUlRE52gdwQ?si=0sWMOi35JoyzSeza

**Advanced Python tool for extracting Protocol Buffer (protobuf) schemas, message definitions, and API structures from iOS IPA applications.**

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Platform: iOS](https://img.shields.io/badge/Platform-iOS-lightgrey.svg)](https://developer.apple.com/ios/)

Perfect for reverse engineering, security research, API analysis, and mobile app development research.

## 🚀 Features

- ✅ **Extract .proto files** from iOS app bundles
- ✅ **Analyze compiled protobuf files** (.pb format)
- ✅ **Advanced binary string analysis** for protobuf patterns
- ✅ **Automatic .proto file reconstruction** with message definitions
- ✅ **Framework and library analysis** for embedded protobufs
- ✅ **Protobuf descriptor search** and extraction
- ✅ **Support for all iOS applications** using Protocol Buffers
- ✅ **Comprehensive reporting** with detailed analysis results
- ✅ **Multi-format output** (JSON, text, reconstructed .proto files)

## 🛠️ Installation

### Prerequisites
- Python 3.6 or higher
- Required Python packages (install automatically)

### Quick Setup
```bash
# Clone the repository
git clone https://github.com/riyadmondol2006/iOS-Protobuf-Extractor.git
cd iOS-Protobuf-Extractor

# Install dependencies
pip3 install -r requirements.txt

# Make executable
chmod +x ios_protobuf_extractor.py
```

### Manual Installation
```bash
# Install required packages manually
pip3 install zipfile36 pathlib
```

## 📱 Usage

### Basic Usage
```bash
# Extract from IPA file to current directory
python3 ios_protobuf_extractor.py app.ipa

# Extract to specific output directory
python3 ios_protobuf_extractor.py app.ipa ./output_folder/

# Show help
python3 ios_protobuf_extractor.py --help
```

### Advanced Usage
```bash
# Verbose mode with detailed logging
python3 ios_protobuf_extractor.py -v app.ipa ./results/

# Extract only specific analysis types
python3 ios_protobuf_extractor.py --strings-only app.ipa

# Custom output format
python3 ios_protobuf_extractor.py --format json app.ipa
```

## 📊 Analysis Methods

The tool employs multiple extraction techniques:

### 1. **Direct .proto File Search**
- Scans for `.proto` files within the IPA bundle
- Extracts human-readable protobuf definitions

### 2. **Compiled Protobuf Analysis**
- Identifies `.pb` files (compiled protobuf)
- Attempts to decompile back to .proto format

### 3. **Binary String Analysis**
- Searches binary files for protobuf-related strings
- Identifies message names, field names, and service definitions
- Reconstructs potential API structures

### 4. **Framework Analysis**
- Scans embedded frameworks for protobuf usage
- Analyzes dynamic libraries and frameworks

### 5. **Descriptor Search**
- Locates protobuf descriptor signatures in binaries
- Extracts compiled message descriptors

## 📁 Output Structure

```
output_folder/
├── README.txt                    # Analysis summary
├── extraction_summary.json       # Detailed results in JSON
├── proto_files/                  # Direct .proto files found
├── compiled_protobufs/          # Compiled .pb files
├── binary_analysis/             # Binary analysis results
│   └── descriptor_*.desc        # Extracted descriptors
└── strings_analysis/            # String analysis results
    ├── protobuf_strings.txt     # All protobuf-related strings
    └── reconstructed_proto.proto # Reconstructed protobuf definitions
```

## 🎯 Common Use Cases

### Security Research
```bash
# Analyze popular apps for API structures
python3 ios_protobuf_extractor.py instagram.ipa ./instagram_analysis/
python3 ios_protobuf_extractor.py whatsapp.ipa ./whatsapp_analysis/
```

### API Reverse Engineering
```bash
# Extract API definitions for integration
python3 ios_protobuf_extractor.py banking_app.ipa ./api_analysis/
```

### Development Research
```bash
# Study protobuf implementation patterns
python3 ios_protobuf_extractor.py various_apps.ipa ./research/
```

## 🔍 Example Output

```
IPA Protobuf Extraction Report
========================================
IPA File: TikTok.ipa
Output Directory: tiktok_analysis
Total Files Found: 127

Results by Method:
--------------------
direct_proto_files: 12 files
compiled_protobuf_files: 8 files
strings_analysis: 45 message types found
framework_analysis: 3 frameworks analyzed
descriptor_search: 15 descriptors extracted

Key Findings:
- User profile management API
- Video upload/streaming protocols
- Chat and messaging system
- Content recommendation engine
- Authentication and security protocols
```

## 🛡️ Applications

### 🔐 Security Research
- API vulnerability assessment
- Protocol analysis for security flaws
- Authentication mechanism research

### 📱 Mobile Development
- Understanding app architecture
- API integration research
- Performance optimization studies

### 🔍 Reverse Engineering
- App functionality analysis
- Feature implementation study
- Competitive analysis

### 🧪 Academic Research
- Mobile protocol analysis
- App behavior studies
- Security research projects

## ⚠️ Legal Notice

This tool is intended for:
- ✅ Educational purposes
- ✅ Security research on apps you own
- ✅ Academic research
- ✅ Legitimate reverse engineering

**Always ensure you have proper authorization before analyzing applications.**

## 🐛 Troubleshooting

### Common Issues

**Issue**: "No protobuf data found"
```bash
# Try with verbose mode to see detailed analysis
python3 ios_protobuf_extractor.py -v app.ipa
```

**Issue**: "Invalid IPA file"
```bash
# Verify IPA file integrity
unzip -t app.ipa
```

**Issue**: "Permission denied"
```bash
# Fix file permissions
chmod +x ios_protobuf_extractor.py
```

### Getting Help

If you encounter issues:
1. Check the verbose output with `-v` flag
2. Verify Python version (3.6+ required)
3. Ensure all dependencies are installed
4. Contact support (details below)

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Submit a pull request

### Development Setup
```bash
git clone https://github.com/riyadmondol2006/iOS-Protobuf-Extractor.git
cd iOS-Protobuf-Extractor
pip3 install -r requirements.txt
```

## 📝 License

MIT License - see [LICENSE](LICENSE) file for details.

## 👨‍💻 Author

**Riyad Mondol** - iOS Security Researcher & Reverse Engineer

For inquiries, support, or project quotes:
- **Email**: [riyadmondol2006@gmail.com](mailto:riyadmondol2006@gmail.com)
- **YouTube**: [Reversesio](https://www.youtube.com/@reversesio)
- **Blog**: [reversesio.com](http://reversesio.com/)
- **Project Quotes**: [reversesio.shop](http://reversesio.shop/)
- **Telegram**: [@riyadmondol2006](https://t.me/riyadmondol2006)

### 🚀 Available for Projects

I'm available for custom reverse engineering projects and consultations:
- 📱 iOS app analysis and reverse engineering
- 🔐 Mobile security assessments
- 🛠️ Custom tool development
- 📊 API analysis and documentation
- 🎓 Training and workshops

Feel free to reach out for any project opportunities!

---

## ⭐ Support

If this tool helped you, please:
- ⭐ Star this repository
- 🐛 Report bugs or request features
- 📢 Share with the community
- 💬 Follow me on social media

**Happy Reverse Engineering! 🕵️‍♂️**
