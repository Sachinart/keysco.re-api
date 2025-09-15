#!/usr/bin/env python3
"""
Keyscore API Search Tool by Chirag Artani
A Python script for searching breach databases using the Keyscore API
Optimized for penetration testing and domain reconnaissance
"""

import requests
import json
import sys
import datetime
from typing import List, Dict, Optional, Union

class KeyscoreAPI:
    def __init__(self, api_key: str):
        """
        Initialize the Keyscore API client
        
        Args:
            api_key (str): Your Keyscore API key
        """
        self.api_key = api_key
        self.base_url = "https://api.keysco.re"
        self.headers = {
            "Authorization": f"Bearer {api_key}",
            "Content-Type": "application/json"
        }
        self.all_sources = ["xkeyscore", "snusbase", "leakcheck", "hackcheck", "oathnet", 
                           "ghosint.leakosint", "ghosint.seon", "ghosint.breachvip", 
                           "osintdog.intelvault", "osintdog.breachbase", "osintdog.akula"]
    
    def search(self, 
               terms: List[str], 
               types: List[str], 
               source: str,
               wildcard: bool = False,
               regex: bool = False,
               operator: str = "OR",
               date_from: Optional[str] = None,
               date_to: Optional[str] = None,
               page: int = 1,
               pages: Optional[Union[str, int]] = None,
               pagesize: int = 10000) -> Dict:
        """Search breach databases"""
        
        # Build request payload
        payload = {
            "terms": terms,
            "types": types,
            "source": source,
            "wildcard": wildcard,
            "regex": regex,
            "operator": operator,
            "page": page,
            "pagesize": pagesize
        }
        
        # Add optional parameters
        if date_from:
            payload["dateFrom"] = date_from
        if date_to:
            payload["dateTo"] = date_to
        if pages:
            payload["pages"] = pages
        
        try:
            response = requests.post(
                f"{self.base_url}/search",
                headers=self.headers,
                json=payload,
                timeout=30
            )
            
            # Handle different status codes
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 400:
                raise Exception("Bad Request: Invalid request body")
            elif response.status_code == 401:
                raise Exception("Unauthorized: Missing or invalid API key")
            elif response.status_code == 402:
                raise Exception("Payment Required: Insufficient credits")
            elif response.status_code == 403:
                raise Exception("Forbidden: Invalid request origin")
            elif response.status_code == 500:
                raise Exception("Internal Server Error")
            else:
                raise Exception(f"Unexpected status code: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            raise Exception(f"Request failed: {str(e)}")
    
    def count(self, terms: List[str], types: List[str], source: str = "xkeyscore",
              wildcard: bool = False, regex: bool = False, operator: str = "OR",
              date_from: Optional[str] = None, date_to: Optional[str] = None) -> Dict:
        """Get count statistics for search terms without retrieving actual results"""
        
        payload = {
            "terms": terms,
            "types": types,
            "source": source,
            "wildcard": wildcard,
            "regex": regex,
            "operator": operator
        }
        
        if date_from:
            payload["dateFrom"] = date_from
        if date_to:
            payload["dateTo"] = date_to
        
        try:
            response = requests.post(
                f"{self.base_url}/count",
                headers=self.headers,
                json=payload,
                timeout=30
            )
            
            if response.status_code == 200:
                return response.json()
            elif response.status_code == 400:
                raise Exception("Bad Request: Invalid request body")
            elif response.status_code == 401:
                raise Exception("Unauthorized: Missing or invalid API key")
            elif response.status_code == 402:
                raise Exception("Payment Required: Insufficient credits")
            else:
                raise Exception(f"Unexpected status code: {response.status_code}")
                
        except requests.exceptions.RequestException as e:
            raise Exception(f"Count request failed: {str(e)}")

    def search_all_sources(self, terms: List[str], types: List[str], search_term: str):
        """Search across ALL sources and return combined results with proper formatting"""
        print(f"🔍 Searching across {len(self.all_sources)} sources...")
        print("📊 This may take a moment as we query multiple databases...")
        
        all_results = {"results": {}, "size": 0, "took": 0}
        successful_sources = 0
        
        for i, source in enumerate(self.all_sources, 1):
            try:
                print(f"   [{i}/{len(self.all_sources)}] Querying {source}...", end=" ")
                
                result = self.search(
                    terms=terms,
                    types=types,
                    source=source
                )
                
                if result.get("results"):
                    found_count = result.get("size", 0)
                    if found_count > 0:
                        print(f"✅ {found_count} results")
                        # Add source prefix to distinguish results
                        for db_name, records in result["results"].items():
                            # Fix N/A issue by adding search term to records
                            for record in records:
                                if types[0] == "email" and record.get('email') in ['N/A', None, '']:
                                    record['email'] = search_term
                                elif types[0] == "url" and record.get('url') in ['N/A', None, '']:
                                    record['url'] = search_term
                                elif types[0] == "username" and record.get('username') in ['N/A', None, '']:
                                    record['username'] = search_term
                            
                            all_results["results"][f"🔸{source}➤{db_name}"] = records
                        all_results["size"] += found_count
                        successful_sources += 1
                    else:
                        print("❌ No results")
                else:
                    print("❌ No results")
                    
                all_results["took"] += result.get("took", 0)
                
            except Exception as e:
                print(f"⚠️ Error: {str(e)}")
                continue
        
        print(f"\n🎯 Search completed! Found data in {successful_sources}/{len(self.all_sources)} sources")
        return all_results

    def search_email_all_sources(self, email: str):
        """Search for email across all sources"""
        return self.search_all_sources([email], ["email"], email)
    
    def search_domain_all_sources(self, domain: str):
        """Search for domain across all sources"""
        return self.search_all_sources([domain], ["url"], domain)
    
    def search_username_all_sources(self, username: str):
        """Search for username across all sources"""
        return self.search_all_sources([username], ["username"], username)

def print_results(results: Dict):
    """Pretty print search results with enhanced formatting - shows ALL available fields"""
    if "results" in results:
        print(f"\n=== 📊 SEARCH RESULTS ===")
        print(f"Total results: {results.get('size', 0)}")
        print(f"Search took: {results.get('took', 0)}ms")
        print("-" * 60)
        
        if results.get('size', 0) == 0:
            print("❌ No results found across any sources")
            return
        
        total_records = 0
        for db_name, records in results["results"].items():
            print(f"\n🗄️  Database: {db_name}")
            print(f"📈 Records found: {len(records)}")
            print("-" * 40)
            
            for i, record in enumerate(records, 1):
                total_records += 1
                print(f"  [{total_records}] Record {i}:")
                
                # Priority fields to show first (if they exist)
                priority_fields = ['email', 'login', 'username', 'user', 'profile', 'nick']
                password_fields = ['password', 'pass', 'pwd']
                url_fields = ['url', 'website', 'site', 'domain']
                
                # Show priority identity fields first
                for field in priority_fields:
                    if field in record and record[field] and record[field] != 'N/A':
                        print(f"      {field.title()}: {record[field]}")
                        break
                
                # Show password fields
                for field in password_fields:
                    if field in record and record[field] and record[field] != 'N/A':
                        print(f"      {field.title()}: {record[field]}")
                        break
                
                # Show URL fields
                for field in url_fields:
                    if field in record and record[field] and record[field] != 'N/A':
                        print(f"      {field.title()}: {record[field]}")
                        break
                
                # Show ALL other fields that aren't in the priority lists
                shown_fields = set(priority_fields + password_fields + url_fields)
                for field, value in record.items():
                    if field.lower() not in shown_fields and value and value != 'N/A':
                        print(f"      {field.replace('_', ' ').title()}: {value}")
                
                print("-" * 30)
        
        print(f"\n📈 Total records displayed: {total_records}")
    else:
        print("❌ No results found or unexpected response format")

def save_results_to_file(results: Dict, search_term: str, search_type: str):
    """Save search results to a formatted text file - includes ALL available fields"""
    
    # Create filename in format: searchterm-type-output.txt
    safe_term = "".join(c for c in search_term if c.isalnum() or c in ('-', '_', '.'))
    filename = f"{safe_term}-{search_type}-output.txt"
    
    try:
        print(f"💾 Preparing to save {results.get('size', 0)} records...")
        
        with open(filename, 'w', encoding='utf-8') as f:
            # Write header
            f.write("="*80 + "\n")
            f.write("KEYSCORE BREACH DATABASE SEARCH RESULTS\n")
            f.write("="*80 + "\n")
            f.write(f"Search Term: {search_term}\n")
            f.write(f"Search Type: {search_type}\n")
            f.write(f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write(f"Total Results: {results.get('size', 0)}\n")
            f.write(f"Search Duration: {results.get('took', 0)}ms\n")
            f.write("="*80 + "\n\n")
            
            if results.get('size', 0) == 0:
                f.write("No results found across any sources.\n")
                print(f"✅ Empty results saved to: {filename}")
                return filename
            
            # Write all results with ALL available fields
            record_count = 0
            total_records = results.get('size', 0)
            
            for db_name, records in results.get("results", {}).items():
                f.write("-" * 60 + "\n")
                f.write(f"🗄️  Database: {db_name}\n")
                f.write(f"📈 Records found: {len(records)}\n")
                f.write("-" * 40 + "\n")
                
                for i, record in enumerate(records, 1):
                    record_count += 1
                    
                    # Show progress for large datasets
                    if record_count % 1000 == 0:
                        print(f"   📝 Writing record {record_count}/{total_records}...")
                    
                    f.write(f"  [{record_count}] Record {i}:\n")
                    
                    # Priority fields to show first (if they exist)
                    priority_fields = ['email', 'login', 'username', 'user', 'profile', 'nick']
                    password_fields = ['password', 'pass', 'pwd']
                    url_fields = ['url', 'website', 'site', 'domain']
                    
                    # Show priority identity fields first
                    for field in priority_fields:
                        if field in record and record[field] and record[field] != 'N/A':
                            f.write(f"      {field.title()}: {record[field]}\n")
                            break
                    
                    # Show password fields
                    for field in password_fields:
                        if field in record and record[field] and record[field] != 'N/A':
                            f.write(f"      {field.title()}: {record[field]}\n")
                            break
                    
                    # Show URL fields
                    for field in url_fields:
                        if field in record and record[field] and record[field] != 'N/A':
                            f.write(f"      {field.title()}: {record[field]}\n")
                            break
                    
                    # Show ALL other fields
                    shown_fields = set(priority_fields + password_fields + url_fields)
                    for field, value in record.items():
                        if field.lower() not in shown_fields and value and value != 'N/A':
                            f.write(f"      {field.replace('_', ' ').title()}: {value}\n")
                    
                    f.write("-" * 30 + "\n")
                
                f.write("\n")
            
            # Write summary
            f.write("="*80 + "\n")
            f.write("SEARCH SUMMARY\n")
            f.write("="*80 + "\n")
            f.write(f"Total Records: {record_count}\n")
            f.write(f"Databases with Results: {len(results.get('results', {}))}\n")
            f.write(f"Search Term: {search_term}\n")
            f.write(f"Search Type: {search_type.upper()}\n")
            f.write(f"File Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("="*80 + "\n")
        
        # Get file size for user info
        import os
        file_size = os.path.getsize(filename)
        if file_size > 1024 * 1024:  # Over 1MB
            size_str = f"{file_size / (1024 * 1024):.1f} MB"
        elif file_size > 1024:  # Over 1KB
            size_str = f"{file_size / 1024:.1f} KB"
        else:
            size_str = f"{file_size} bytes"
        
        print(f"✅ Results saved successfully!")
        print(f"   📁 File: {filename}")
        print(f"   📊 Records: {record_count:,}")
        print(f"   💾 Size: {size_str}")
        return filename
        
    except PermissionError:
        print(f"❌ Permission denied: Cannot write to {filename}")
        print("   💡 Try running with different permissions or change directory")
        return None
    except OSError as e:
        print(f"❌ File system error: {str(e)}")
        print("   💡 Check disk space and file path validity")
        return None
    except MemoryError:
        print(f"❌ Not enough memory to save {results.get('size', 0)} records")
        print("   💡 Try searching with smaller result sets or increase system memory")
        return None
    except Exception as e:
        print(f"❌ Unexpected error saving file: {str(e)}")
        print(f"   💡 Error type: {type(e).__name__}")
        return None

def print_count_results(count_data: Dict, search_terms: List[str], search_type: str):
    """Pretty print count results"""
    print(f"\n=== 📊 COUNT RESULTS ===")
    print(f"Search terms: {', '.join(search_terms)}")
    print(f"Search type: {search_type}")
    print("-" * 50)
    
    if "count" in count_data:
        count = count_data.get("count", 0)
        print(f"🔢 Total records available: {count:,}")
        
        if count > 0:
            print(f"💰 Estimated credits for full search:")
            print(f"   - Single page: 1 credit (up to 10,000 records)")
            if count > 10000:
                pages_needed = (count // 10000) + 1
                print(f"   - All data: ~{pages_needed} credits ({pages_needed} pages)")
        else:
            print("❌ No records found for this search")
    
    elif "counts" in count_data and "total_count" in count_data:
        total_count = count_data.get("total_count", 0)
        took = count_data.get("took", 0)
        counts = count_data.get("counts", {})
        
        print(f"🔢 Total records available: {total_count:,}")
        print(f"⏱️  Search took: {took}ms")
        print("\n📊 Breakdown by source:")
        
        for source, count in counts.items():
            if count > 0:
                print(f"   ✅ {source}: {count:,} records")
            else:
                print(f"   ❌ {source}: No records")
        
        if total_count > 0:
            print(f"\n💰 Estimated credits for full search:")
            print(f"   - Single page: 1 credit (up to 10,000 records)")
            if total_count > 10000:
                pages_needed = (total_count // 10000) + 1
                print(f"   - All data: ~{pages_needed} credits ({pages_needed} pages)")
    else:
        print("❌ Unexpected response format")

def count_all_sources(api: KeyscoreAPI, terms: List[str], types: List[str]):
    """Get count from all sources"""
    print(f"📊 Getting counts from all sources...")
    
    total_count = 0
    source_counts = {}
    
    for source in api.all_sources:
        try:
            print(f"   Counting {source}...", end=" ")
            result = api.count(terms=terms, types=types, source=source)
            count = result.get('count', 0)
            source_counts[source] = count
            total_count += count
            print(f"{count:,} results")
        except Exception as e:
            print(f"Error: {str(e)}")
            source_counts[source] = 0
    
    return {
        "total_count": total_count,
        "counts": source_counts,
        "took": 0
    }

def main():
    """Interactive Domain/URL Search Tool for Penetration Testing"""
    
    # Your API key is configured here
    API_KEY = "place-your-api-key"
    
    # Initialize API client
    api = KeyscoreAPI(API_KEY)
    
    try:
        print("🔐 KEYSCORE BREACH DATABASE SEARCH TOOL")
        print("🎯 Specialized for Penetration Testing & Domain Intelligence")
        print("="*60)
        print("💡 Perfect for OSINT and reconnaissance!")
        print(f"🌐 Searches across {len(api.all_sources)} breach databases!")
        
        while True:
            print("\n" + "="*60)
            print("🚀 MAIN MENU")
            print("="*60)
            print("1. 🎯 Comprehensive Domain Search")
            print("2. 🔍 Quick Domain Lookup (ALL SOURCES)")
            print("3. 📧 Email Search (ALL SOURCES)")
            print("4. 👤 Username Search (ALL SOURCES)")
            print("5. 🔎 Wildcard Search")
            print("6. 📊 Count Check (Before Full Search)")
            print("7. ℹ️  Show API Info")
            print("8. 🚪 Exit")
            
            choice = input("\n👉 Enter your choice (1-8): ").strip()
            
            if choice == "1":
                print("\n🎯 Comprehensive Domain Search")
                print("This option uses the original search configuration...")
                print("Feature coming soon - use options 2-4 for multi-source searches!")
                
            elif choice == "2":
                domain = input("\n🔍 Enter domain for lookup: ").strip()
                if domain:
                    print(f"\n🚀 Searching for domain: {domain}")
                    try:
                        results = api.search_domain_all_sources(domain)
                        print_results(results)
                        
                        if results.get('size', 0) > 0:
                            save_choice = input("\n💾 Save results to file? (y/n): ").strip().lower()
                            if save_choice == 'y':
                                save_results_to_file(results, domain, "domain")
                                
                    except Exception as e:
                        print(f"❌ Error: {str(e)}")
                        
            elif choice == "3":
                email = input("\n📧 Enter email address to search: ").strip()
                if email:
                    print(f"\n🚀 Searching for email: {email}")
                    try:
                        results = api.search_email_all_sources(email)
                        print_results(results)
                        
                        if results.get('size', 0) > 0:
                            save_choice = input("\n💾 Save results to file? (y/n): ").strip().lower()
                            if save_choice == 'y':
                                save_results_to_file(results, email, "email")
                                
                    except Exception as e:
                        print(f"❌ Error: {str(e)}")
                        
            elif choice == "4":
                username = input("\n👤 Enter username to search: ").strip()
                if username:
                    print(f"\n🚀 Searching for username: {username}")
                    try:
                        results = api.search_username_all_sources(username)
                        print_results(results)
                        
                        if results.get('size', 0) > 0:
                            save_choice = input("\n💾 Save results to file? (y/n): ").strip().lower()
                            if save_choice == 'y':
                                save_results_to_file(results, username, "username")
                                
                    except Exception as e:
                        print(f"❌ Error: {str(e)}")
                        
            elif choice == "5":
                pattern = input("\n🔎 Enter wildcard pattern (e.g., *.target.com): ").strip()
                if pattern:
                    source = input("🗄️  Enter source (default: xkeyscore): ").strip() or "xkeyscore"
                    print(f"\n🚀 Wildcard search: {pattern}")
                    try:
                        results = api.search(
                            terms=[pattern],
                            types=["url"],
                            source=source,
                            wildcard=True
                        )
                        print_results(results)
                        
                        if results.get('size', 0) > 0:
                            save_choice = input("\n💾 Save results to file? (y/n): ").strip().lower()
                            if save_choice == 'y':
                                save_results_to_file(results, pattern, "wildcard")
                                
                    except Exception as e:
                        print(f"❌ Error: {str(e)}")
                        
            elif choice == "6":
                print("\n📊 COUNT CHECK")
                print("="*30)
                
                search_term = input("🔍 Enter search term: ").strip()
                if search_term:
                    print("\n📋 Search type:")
                    print("1. Domain/URL")
                    print("2. Email")
                    print("3. Username")
                    
                    type_choice = input("Select type (1-3): ").strip()
                    type_map = {'1': ['url'], '2': ['email'], '3': ['username']}
                    
                    if type_choice in type_map:
                        try:
                            count_result = count_all_sources(api, [search_term], type_map[type_choice])
                            print_count_results(count_result, [search_term], type_map[type_choice][0])
                        except Exception as e:
                            print(f"❌ Count error: {str(e)}")
                    else:
                        print("❌ Invalid choice")
                        
            elif choice == "7":
                print("\n📊 KEYSCORE API INFORMATION")
                print("="*50)
                print("💰 Credits:")
                print("   • Each search = 1 credit per source")
                print("   • Each count = 1 credit per source")
                print("   • Multi-page: Credits = pages × sources")
                print(f"\n🗄️  Available Sources ({len(api.all_sources)}):")
                for i, source in enumerate(api.all_sources, 1):
                    print(f"   {i}. {source}")
                print("\n🔍 Search Types:")
                print("   • url: Domain/URL searches")
                print("   • email: Email address searches")
                print("   • username: Username searches")
                print("   • password: Password searches")
                print("   • phone: Phone number searches")
                print("   • name: Full name searches")
                print("\n🚀 Multi-Source Features:")
                print("   • Options 2-4 search ALL sources automatically")
                print("   • Shows actual search terms (no more N/A)")
                print("   • Source-prefixed database names for clarity")
                print("   • Real-time progress indicators")
                print("   • Auto-save option with custom filenames")
                        
            elif choice == "8":
                print("\n👋 Happy hunting! Stay safe and legal! 🔒")
                break
                
            else:
                print("❌ Invalid choice. Please try again.")
        
    except KeyboardInterrupt:
        print("\n\n👋 Search interrupted by user. Goodbye!")
    except Exception as e:
        print(f"❌ Unexpected error: {str(e)}")

if __name__ == "__main__":
    main()
