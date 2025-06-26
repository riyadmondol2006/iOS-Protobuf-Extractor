#!/usr/bin/env python3
"""
iOS Protobuf Extractor - Advanced IPA Analysis Tool
==================================================

A comprehensive Python tool for extracting Protocol Buffer (protobuf) schemas, 
message definitions, and API structures from iOS IPA applications.

Features:
- Extract .proto files from iOS app bundles
- Analyze compiled protobuf files (.pb)
- Binary string analysis for protobuf patterns
- Automatic .proto file reconstruction
- Framework and library analysis
- Protobuf descriptor search and extraction
- Support for all iOS applications using protobuf

Perfect for:
- Reverse engineering iOS applications
- API structure analysis
- Security research and penetration testing
- Mobile app development research
- Protocol analysis and documentation

Author: Riyad Mondol
Website: http://reversesio.com/ | http://reversesio.shop/
Contact: riyadmondol2006@gmail.com
Telegram: https://t.me/riyadmondol2006
YouTube: https://www.youtube.com/@reversesio

For inquiries, support, or project quotes:
- Email: riyadmondol2006@gmail.com
- YouTube: https://www.youtube.com/@reversesio
- Blog: http://reversesio.com/
- Project Quotes: http://reversesio.shop/
- Telegram: @riyadmondol2006

Feel free to reach out for any reverse engineering projects or collaborations!

License: MIT License
Version: 1.0.0
Python: 3.6+
"""

import os
import sys
import zipfile
import logging
import json
import re
from pathlib import Path
from datetime import datetime
import argparse
import struct

# Set up logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

# Author information
__author__ = "Riyad Mondol"
__email__ = "riyadmondol2006@gmail.com"
__website__ = "http://reversesio.com/"
__telegram__ = "https://t.me/riyadmondol2006"
__version__ = "1.0.0"

def print_banner():
    """Print tool banner with author information"""
    banner = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                          iOS Protobuf Extractor v{__version__}                         ║
║                     Advanced IPA Analysis & Reverse Engineering              ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ Author: {__author__:<63} ║
║ Website: {__website__:<62} ║
║ Contact: {__email__:<62} ║
║ Telegram: {__telegram__:<61} ║
║ YouTube: https://www.youtube.com/@reversesio                                 ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ 🔍 Extract protobuf schemas from any iOS application                         ║
║ 🛠️  Advanced binary analysis and string extraction                           ║
║ 📱 Support for all iOS apps using Protocol Buffers                          ║
║ 🔧 Automatic .proto file reconstruction                                      ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(banner)

def print_footer():
    """Print footer with contact information"""
    footer = f"""
╔══════════════════════════════════════════════════════════════════════════════╗
║                               Need Help?                                     ║
╠══════════════════════════════════════════════════════════════════════════════╣
║ 📧 Email: {__email__:<62} ║
║ 🌐 Website: {__website__:<60} ║
║ 🛒 Project Quotes: http://reversesio.shop/                                  ║
║ 📱 Telegram: {__telegram__:<59} ║
║ 🎥 YouTube: https://www.youtube.com/@reversesio                             ║
║                                                                              ║
║ Available for custom reverse engineering projects and consultations!        ║
╚══════════════════════════════════════════════════════════════════════════════╝
    """
    print(footer)

class ProtobufExtractor:
    def __init__(self, ipa_path, output_dir):
        self.ipa_path = Path(ipa_path)
        self.output_dir = Path(output_dir)
        self.temp_dir = None
        self.results = {
            'direct_proto_files': [],
            'compiled_protobuf_files': [],
            'strings_analysis': [],
            'framework_analysis': [],
            'descriptor_search': []
        }
        
    def extract_ipa(self):
        """Extract IPA file to temporary directory"""
        logger.info("Extracting IPA file...")
        self.temp_dir = self.output_dir / "temp_extract"
        self.temp_dir.mkdir(parents=True, exist_ok=True)
        
        try:
            with zipfile.ZipFile(self.ipa_path, 'r') as zip_ref:
                zip_ref.extractall(self.temp_dir)
            
            # Find the .app bundle
            app_bundles = list(self.temp_dir.glob("Payload/*.app"))
            if not app_bundles:
                raise ValueError("No .app bundle found in IPA")
            
            self.app_bundle = app_bundles[0]
            logger.info(f"Found app bundle: {self.app_bundle.name}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to extract IPA: {e}")
            return False
    
    def search_direct_proto_files(self):
        """Search for direct .proto files in the app bundle"""
        logger.info("Searching for direct .proto files...")
        proto_files = list(self.app_bundle.rglob("*.proto"))
        
        for proto_file in proto_files:
            try:
                with open(proto_file, 'r', encoding='utf-8', errors='ignore') as f:
                    content = f.read()
                
                output_file = self.output_dir / "proto_files" / proto_file.name
                output_file.parent.mkdir(parents=True, exist_ok=True)
                
                with open(output_file, 'w') as f:
                    f.write(content)
                
                self.results['direct_proto_files'].append({
                    'file': str(proto_file.relative_to(self.app_bundle)),
                    'size': proto_file.stat().st_size,
                    'output': str(output_file.relative_to(self.output_dir))
                })
                
            except Exception as e:
                logger.warning(f"Failed to process proto file {proto_file}: {e}")
    
    def search_compiled_protobuf_files(self):
        """Search for compiled protobuf files (.pb)"""
        logger.info("Searching for compiled protobuf files...")
        pb_files = list(self.app_bundle.rglob("*.pb"))
        
        for pb_file in pb_files:
            try:
                output_file = self.output_dir / "compiled_protobufs" / pb_file.name
                output_file.parent.mkdir(parents=True, exist_ok=True)
                
                # Copy the file
                with open(pb_file, 'rb') as src, open(output_file, 'wb') as dst:
                    dst.write(src.read())
                
                self.results['compiled_protobuf_files'].append({
                    'file': str(pb_file.relative_to(self.app_bundle)),
                    'size': pb_file.stat().st_size,
                    'output': str(output_file.relative_to(self.output_dir))
                })
                
            except Exception as e:
                logger.warning(f"Failed to process pb file {pb_file}: {e}")
    
    def analyze_main_binary(self):
        """Analyze the main binary for protobuf strings"""
        logger.info("Analyzing main binary...")
        
        # Find main executable
        binary_name = self.app_bundle.name.replace('.app', '')
        binary_path = self.app_bundle / binary_name
        
        if not binary_path.exists():
            logger.warning(f"Main binary not found: {binary_path}")
            return
        
        try:
            logger.info(f"Analyzing binary: {binary_name}")
            self.extract_strings_from_binary(binary_path)
        except Exception as e:
            logger.error(f"Failed to analyze binary: {e}")
    
    def extract_strings_from_binary(self, binary_path):
        """Extract protobuf-related strings from binary"""
        logger.info("Performing strings analysis...")
        
        try:
            with open(binary_path, 'rb') as f:
                binary_data = f.read()
            
            # Protobuf-related patterns
            protobuf_patterns = [
                rb'\.proto',
                rb'protobuf',
                rb'Request',
                rb'Response',
                rb'Message',
                rb'Service',
                rb'rpc ',
                rb'message ',
                rb'service ',
                rb'google\.protobuf',
                rb'SwiftProtobuf',
                rb'UnitySwiftProtobuf',
                rb'_protobuf',
                rb'Protobuf',
                rb'API\w*Request',
                rb'API\w*Response',
            ]
            
            found_strings = set()
            
            # Extract strings using various methods
            for i in range(len(binary_data) - 4):
                # Look for printable strings
                for min_length in [4, 8, 16]:
                    if i + min_length <= len(binary_data):
                        potential_string = binary_data[i:i+min_length]
                        if self.is_printable_string(potential_string):
                            # Extend the string
                            end = i + min_length
                            while end < len(binary_data) and binary_data[end:end+1].isalnum() or binary_data[end:end+1] in b'._':
                                end += 1
                            
                            full_string = binary_data[i:end]
                            if self.contains_protobuf_pattern(full_string, protobuf_patterns):
                                found_strings.add(full_string.decode('utf-8', errors='ignore'))
            
            # Save protobuf strings
            strings_dir = self.output_dir / "strings_analysis"
            strings_dir.mkdir(parents=True, exist_ok=True)
            
            strings_file = strings_dir / "protobuf_strings.txt"
            with open(strings_file, 'w') as f:
                for string in sorted(found_strings):
                    f.write(string + '\n')
            
            # Generate reconstructed proto file
            self.generate_reconstructed_proto(found_strings, strings_dir)
            
            logger.info(f"Found {len(found_strings)} protobuf-related strings")
            
        except Exception as e:
            logger.error(f"String analysis failed: {e}")
    
    def is_printable_string(self, data):
        """Check if data represents a printable string"""
        try:
            decoded = data.decode('utf-8')
            return all(c.isprintable() or c.isspace() for c in decoded)
        except:
            return False
    
    def contains_protobuf_pattern(self, data, patterns):
        """Check if data contains protobuf-related patterns"""
        for pattern in patterns:
            if pattern in data:
                return True
        return False
    
    def generate_reconstructed_proto(self, strings, output_dir):
        """Generate a reconstructed .proto file from found strings"""
        logger.info("Generating reconstructed proto file...")
        
        messages = set()
        services = set()
        rpcs = set()
        
        for string in strings:
            # Look for message patterns
            if 'Request' in string and not string.startswith('_'):
                messages.add(string.strip())
            if 'Response' in string and not string.startswith('_'):
                messages.add(string.strip())
            if 'Message' in string and not string.startswith('_'):
                messages.add(string.strip())
            if 'Service' in string and not string.startswith('_'):
                services.add(string.strip())
        
        # Generate proto file
        proto_content = 'syntax = "proto3";\n\n'
        
        # Add messages
        for message in sorted(messages):
            if self.is_valid_message_name(message):
                proto_content += f'message {message} {{\n'
                proto_content += '  // Fields reconstructed from string analysis\n'
                proto_content += '}\n\n'
        
        # Add services
        for service in sorted(services):
            if self.is_valid_service_name(service):
                proto_content += f'service {service} {{\n'
                proto_content += '  // RPCs reconstructed from string analysis\n'
                proto_content += '}\n\n'
        
        # Save reconstructed proto
        reconstructed_file = output_dir / "reconstructed_proto.proto"
        with open(reconstructed_file, 'w') as f:
            f.write(proto_content)
    
    def is_valid_message_name(self, name):
        """Check if string is a valid protobuf message name"""
        if len(name) < 3 or len(name) > 100:
            return False
        if not name[0].isupper():
            return False
        if not all(c.isalnum() or c == '_' for c in name):
            return False
        return True
    
    def is_valid_service_name(self, name):
        """Check if string is a valid protobuf service name"""
        return self.is_valid_message_name(name)
    
    def search_frameworks(self):
        """Search frameworks for protobuf usage"""
        logger.info("Searching frameworks for protobufs...")
        frameworks_dir = self.app_bundle / "Frameworks"
        
        if not frameworks_dir.exists():
            logger.info("No Frameworks directory found")
            return
        
        for framework in frameworks_dir.iterdir():
            if framework.is_dir() and framework.suffix == '.framework':
                self.analyze_framework(framework)
    
    def analyze_framework(self, framework_path):
        """Analyze individual framework for protobuf content"""
        try:
            # Look for binary in framework
            framework_name = framework_path.name.replace('.framework', '')
            binary_path = framework_path / framework_name
            
            if binary_path.exists():
                logger.info(f"Analyzing framework: {framework_name}")
                # Perform basic analysis
                self.results['framework_analysis'].append({
                    'framework': framework_name,
                    'path': str(framework_path.relative_to(self.app_bundle)),
                    'binary_size': binary_path.stat().st_size if binary_path.exists() else 0
                })
        except Exception as e:
            logger.warning(f"Failed to analyze framework {framework_path}: {e}")
    
    def search_protobuf_descriptors(self):
        """Search for protobuf descriptor signatures in binaries"""
        logger.info("Searching for protobuf descriptors...")
        
        binary_name = self.app_bundle.name.replace('.app', '')
        binary_path = self.app_bundle / binary_name
        
        if not binary_path.exists():
            return
        
        try:
            with open(binary_path, 'rb') as f:
                binary_data = f.read()
            
            # Look for protobuf descriptor signatures
            descriptor_signatures = [
                b'\x08\x96\x01\x12',  # Common protobuf descriptor pattern
                b'\x0a\x04',          # String field pattern
                b'\x12\x04',          # Another common pattern
            ]
            
            descriptor_dir = self.output_dir / "binary_analysis"
            descriptor_dir.mkdir(parents=True, exist_ok=True)
            
            for i, signature in enumerate(descriptor_signatures):
                offset = 0
                count = 0
                while True:
                    offset = binary_data.find(signature, offset)
                    if offset == -1:
                        break
                    
                    # Extract potential descriptor
                    descriptor_data = binary_data[offset:offset+1024]  # Extract 1KB
                    
                    if len(descriptor_data) >= 64:  # Minimum size check
                        descriptor_file = descriptor_dir / f"descriptor_{offset:08x}.desc"
                        with open(descriptor_file, 'wb') as f:
                            f.write(descriptor_data)
                        
                        self.results['descriptor_search'].append({
                            'offset': hex(offset),
                            'signature': signature.hex(),
                            'file': str(descriptor_file.relative_to(self.output_dir))
                        })
                        count += 1
                    
                    offset += 1
                
                if count > 0:
                    logger.info(f"Found descriptor signature in: {binary_name}")
        
        except Exception as e:
            logger.error(f"Descriptor search failed: {e}")
    
    def generate_summary_report(self):
        """Generate summary report"""
        logger.info("Summary report generated")
        
        total_files = (len(self.results['direct_proto_files']) + 
                      len(self.results['compiled_protobuf_files']) + 
                      len(self.results['descriptor_search']))
        
        # Generate text summary
        summary_text = f"""IPA Protobuf Extraction Report
========================================
IPA File: {self.ipa_path.name}
Output Directory: {self.output_dir.name}
Total Files Found: {total_files}

Results by Method:
--------------------
direct_proto_files: {len(self.results['direct_proto_files'])} files
compiled_protobuf_files: {len(self.results['compiled_protobuf_files'])} files
strings_analysis: {len(self.results['strings_analysis'])} files
framework_analysis: {len(self.results['framework_analysis'])} files
descriptor_search: {len(self.results['descriptor_search'])} files

Output Structure:
---------------
proto_files/          - Direct .proto files found
compiled_protobufs/   - Compiled protobuf files (.pb)
binary_analysis/      - Binary analysis results
strings_analysis/     - String extraction results
extraction_summary.json - This summary in JSON format"""

        # Save text summary
        with open(self.output_dir / "README.txt", 'w') as f:
            f.write(summary_text)
        
        # Save JSON summary
        json_summary = {
            'ipa_file': str(self.ipa_path.name),
            'extraction_timestamp': str(self.output_dir),
            'total_methods': 5,
            'summary_by_method': {
                'direct_proto_files': len(self.results['direct_proto_files']),
                'compiled_protobuf_files': len(self.results['compiled_protobuf_files']),
                'strings_analysis': len(self.results['strings_analysis']),
                'framework_analysis': len(self.results['framework_analysis']),
                'descriptor_search': len(self.results['descriptor_search'])
            },
            'total_files_found': total_files
        }
        
        with open(self.output_dir / "extraction_summary.json", 'w') as f:
            json.dump(json_summary, f, indent=2)
        
        logger.info(f"Total protobuf artifacts found: {total_files}")
    
    def cleanup(self):
        """Clean up temporary files"""
        if self.temp_dir and self.temp_dir.exists():
            import shutil
            shutil.rmtree(self.temp_dir)
    
    def extract(self):
        """Main extraction method"""
        try:
            # Create output directory
            self.output_dir.mkdir(parents=True, exist_ok=True)
            
            # Extract IPA
            if not self.extract_ipa():
                return False
            
            # Run all extraction methods
            self.search_direct_proto_files()
            self.search_compiled_protobuf_files()
            self.analyze_main_binary()
            self.search_frameworks()
            self.search_protobuf_descriptors()
            
            # Generate summary
            self.generate_summary_report()
            
            logger.info(f"Extraction complete. Results saved to: {self.output_dir}")
            return True
            
        except Exception as e:
            logger.error(f"Extraction failed: {e}")
            return False
        finally:
            self.cleanup()

def main():
    print_banner()
    
    parser = argparse.ArgumentParser(
        description="Extract protobuf schemas from iOS IPA files",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"""
Examples:
  {sys.argv[0]} app.ipa
  {sys.argv[0]} app.ipa ./output_folder/
  {sys.argv[0]} -v app.ipa ./results/

Author: {__author__}
Contact: {__email__}
Website: {__website__}
        """
    )
    
    parser.add_argument('ipa_file', help='Path to IPA file')
    parser.add_argument('output_dir', nargs='?', default='./output_folder', 
                       help='Output directory (default: ./output_folder)')
    parser.add_argument('-v', '--verbose', action='store_true', 
                       help='Enable verbose logging')
    parser.add_argument('--version', action='version', version=f'%(prog)s {__version__}')
    
    args = parser.parse_args()
    
    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Validate IPA file
    ipa_path = Path(args.ipa_file)
    if not ipa_path.exists():
        logger.error(f"IPA file not found: {ipa_path}")
        sys.exit(1)
    
    if not ipa_path.suffix.lower() == '.ipa':
        logger.error(f"File is not an IPA: {ipa_path}")
        sys.exit(1)
    
    # Run extraction
    extractor = ProtobufExtractor(ipa_path, args.output_dir)
    
    logger.info(f"Starting protobuf extraction from: {ipa_path.name}")
    
    if extractor.extract():
        print(f"\nExtraction completed successfully!")
        print(f"Results saved to: {args.output_dir}")
        print(f"Check 'README.txt' in the output directory for a summary.")
    else:
        print(f"\nExtraction failed. Check logs for details.")
        sys.exit(1)
    
    print_footer()

if __name__ == "__main__":
    main()
