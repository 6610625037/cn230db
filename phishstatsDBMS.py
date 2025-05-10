import os
import subprocess
import sys

def install_package(package_name):
    try:
        __import__(package_name) 
    except ImportError:
        print(f"Library {package_name} not found, installing...")
        subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])

install_package('requests')
install_package('pyfiglet')
install_package('folium')
install_package('scikit-learn')
install_package('termcolor')
install_package('colorama')


import requests
import pyfiglet
import sqlite3
import json
import folium
from folium.plugins import HeatMap
from urllib.parse import urlparse
from sklearn.cluster import KMeans
import numpy as np
import webbrowser
import datetime
import csv
from termcolor import colored
from colorama import Fore, Back, Style, init
from time import sleep



os.system('cls' if os.name == 'nt' else 'clear')

ascii_art = pyfiglet.figlet_format("PHISHTATS", font="slant")
print(ascii_art)
print("API : https://phishstats.info:2096/api/phishing\n")


def get_user_input():
    while True:
        try:
            total_records = int(input("Please enter the number of records to retrieve (a round hundred number / maximum 700 records): "))
            if total_records <= 0 or total_records > 700:
                print("Please enter a number greater than 100 and no more than 700.")
            else:
                return total_records
        except ValueError:
            print("Please enter a numeric value.")


total_records = get_user_input()
page_size = 100  

def fetch_phishing_data(total_records, page_size):
    all_data = []
    pages = total_records // page_size + (1 if total_records % page_size > 0 else 0) 
    for page in range(pages):
        print(f"🔄 Retrieving page {page} (limit {page_size})...")
        api_url = f"https://phishstats.info:2096/api/phishing?_p={page}&_size={page_size}"
        response = requests.get(api_url)
        if response.status_code == 200:
            print(f"✅ Page {page}: Retrieved {len(all_data)} records")
            all_data.extend(response.json())
            if len(all_data) == 0:
                print(f"⚠️ No data returned on page {page}. API might be limited to fewer records.")
                break
        else:
            print(f"❌ Failed to retrieve page {page}. Status code: {response.status_code}.")
            break
    return all_data

phishing_data = fetch_phishing_data(total_records, page_size)

conn = sqlite3.connect("phishing.db")
cur = conn.cursor()

cur.execute(''' 
CREATE TABLE IF NOT EXISTS phishing (
    abuse_ch_malware TEXT,
    abuse_contact TEXT,
    alexa_rank_domain INTEGER,
    alexa_rank_host INTEGER,
    asn TEXT,
    bgp TEXT,
    city TEXT,
    countrycode TEXT,
    countryname TEXT,
    date TEXT,
    date_update TEXT,
    domain TEXT,
    domain_registered_n_days_ago INTEGER,
    google_safebrowsing TEXT,
    hash TEXT,
    host TEXT,
    http_code INTEGER,
    http_server TEXT,
    id INTEGER PRIMARY KEY,
    ip TEXT,
    isp TEXT,
    latitude REAL,
    longitude REAL,
    n_times_seen_domain INTEGER,
    n_times_seen_host INTEGER,
    n_times_seen_ip INTEGER,
    os TEXT,
    page_text TEXT,
    ports TEXT,
    regioncode TEXT,
    regionname TEXT,
    score REAL,
    screenshot TEXT,
    ssl_issuer TEXT,
    ssl_subject TEXT,
    tags TEXT,
    technology TEXT,
    threat_crowd TEXT,
    threat_crowd_subdomain_count INTEGER,
    threat_crowd_votes INTEGER,
    title TEXT,
    tld TEXT,
    url TEXT,
    virus_total TEXT,
    vulns TEXT,
    zipcode TEXT
)
''')

for entry in phishing_data:
    cur.execute(''' 
        INSERT OR REPLACE INTO phishing VALUES (
            :abuse_ch_malware, :abuse_contact,
            :alexa_rank_domain, :alexa_rank_host,
            :asn, :bgp, :city, :countrycode, :countryname,
            :date, :date_update, :domain, :domain_registered_n_days_ago,
            :google_safebrowsing, :hash, :host, :http_code, :http_server,
            :id, :ip, :isp, :latitude, :longitude,
            :n_times_seen_domain, :n_times_seen_host, :n_times_seen_ip,
            :os, :page_text, :ports, :regioncode, :regionname,
            :score, :screenshot, :ssl_issuer, :ssl_subject,
            :tags, :technology, :threat_crowd,
            :threat_crowd_subdomain_count, :threat_crowd_votes,
            :title, :tld, :url, :virus_total, :vulns, :zipcode
        )
    ''', {
        key: (
            json.dumps(entry.get(key)) if isinstance(entry.get(key), (list, dict))
            else entry.get(key)
        )
        for key in [
            'abuse_ch_malware', 'abuse_contact',
            'alexa_rank_domain', 'alexa_rank_host',
            'asn', 'bgp', 'city', 'countrycode', 'countryname',
            'date', 'date_update', 'domain', 'domain_registered_n_days_ago',
            'google_safebrowsing', 'hash', 'host', 'http_code', 'http_server',
            'id', 'ip', 'isp', 'latitude', 'longitude',
            'n_times_seen_domain', 'n_times_seen_host', 'n_times_seen_ip',
            'os', 'page_text', 'ports', 'regioncode', 'regionname',
            'score', 'screenshot', 'ssl_issuer', 'ssl_subject',
            'tags', 'technology', 'threat_crowd',
            'threat_crowd_subdomain_count', 'threat_crowd_votes',
            'title', 'tld', 'url', 'virus_total', 'vulns', 'zipcode'
        ]
    })

conn.commit()

print("-------------------------------------------------------\n")


#------------------------#
#        ANALYSIS        #
#------------------------#

# Geolocation

def normalize_text(text):
    return text.strip().lower()

def export_data(data, filename, export_type="csv"):
    if export_type == "csv":
        with open(filename, "w", newline='', encoding='utf-8') as f:
            writer = csv.DictWriter(f, fieldnames=data[0].keys())
            writer.writeheader()
            writer.writerows(data)
    elif export_type == "json":
        with open(filename, "w", encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    print(f"\n📁 Data has been saved at: {filename}")
    
def show_all_countries(cursor):
    cursor.execute("SELECT DISTINCT countryname FROM phishing WHERE countryname IS NOT NULL ORDER BY countryname ASC")
    countries = [row[0] for row in cursor.fetchall()]
    
    print(f"\nA total of {len(countries)} countries found:")
    for c in countries:
        print(f"- {c}")


def search_country_data_extended(cursor):
    cursor.execute("SELECT DISTINCT countryname FROM phishing WHERE countryname IS NOT NULL")
    raw_countries = [row[0] for row in cursor.fetchall()]
    country_map = {normalize_text(c): c for c in raw_countries}

    while True:
        user_input = input("Please enter the name of the country you want to search for: ")
        norm_input = normalize_text(user_input)

        if norm_input in country_map:
            country = country_map[norm_input]
            
            cursor.execute('''
                SELECT * FROM phishing 
                WHERE countryname = ?
            ''', (country,))
            columns = [desc[0] for desc in cursor.description]
            rows = cursor.fetchall()

            print(f"\nAll data for country: {country} ({len(rows)} records)\n")

            filtered_data = []
            for row in rows:
                row_dict = {col: val for col, val in zip(columns, row) if val not in (None, "", "NULL")}
                filtered_data.append(row_dict)
                for key, value in row_dict.items():
                    print(f"{key}: {value}")
                print("-" * 60)

            if filtered_data:
                export = input("Do you want to export the data as a file? (y/n): ").strip().lower()
                if export == "y":
                    export_type = input("Select format csv or json: ").strip().lower()
                    export_data(filtered_data, f"full_data_{country}.{export_type}", export_type)
            else:
                print("There is no non-empty data for this country.")
            break
        else:
            candidates = [orig for norm, orig in country_map.items() if norm.startswith(norm_input[:3])]
            if candidates:
                print("\nNo exact match found. Try these similar country names:")
                for c in candidates:
                    print(f"- {c}")
            else:
                print("\nCountry not found. Please try again.")
                
#search_country_data_extended(cur)

def analyze_phishing_by_country(cursor, limit=10):

    print("\nCountries with the most phishing websites:")
    cursor.execute('''
        SELECT countryname, COUNT(*) as total
        FROM phishing
        WHERE countryname IS NOT NULL
        GROUP BY countryname
        ORDER BY total DESC
        LIMIT ?
    ''', (limit,))
    rows = cursor.fetchall()

    for idx, row in enumerate(rows, 1):
        print(f"{idx}. Country: {row[0]} - Records: {row[1]}")

#analyze_phishing_by_country(cur)

def get_top_phishing_cities_with_country(cursor, limit=10):

    cursor.execute('''
        SELECT city, countryname, COUNT(*) as total
        FROM phishing
        WHERE city IS NOT NULL AND city != ''
              AND countryname IS NOT NULL AND countryname != ''
        GROUP BY city, countryname
        ORDER BY total DESC
        LIMIT ?
    ''', (limit,))

    results = cursor.fetchall()

    if not results:
        print("No city and country data related to phishing activity found.")
        return

    print(f"\nMost frequently found cities in phishing activity, along with their countries. (Top {limit}):")
    for rank, (city, country, total) in enumerate(results, start=1):
        print(f"{rank}. {city}, {country}: {total} times")

#get_top_phishing_cities_with_country(cur, limit=10)

def generate_phishing_heatmap(cursor, output_file="phishing_heatmap.html", min_records=10):

    cursor.execute('''
        SELECT latitude, longitude
        FROM phishing
        WHERE latitude IS NOT NULL AND longitude IS NOT NULL
    ''')

    results = cursor.fetchall()
    locations = [(lat, lon) for lat, lon in results if lat and lon]

    if len(locations) < min_records:
        print("Insufficient coordinate data to generate heatmap")
        return

    m = folium.Map(location=[0, 0], zoom_start=2, tiles='CartoDB dark_matter')

    HeatMap(locations, radius=8, blur=15, min_opacity=0.4).add_to(m)

    m.save(output_file)
    print(f"Heatmap created successfully! Open the file {output_file} to view the result.")
    export = input("Would you like to open the file? ⚠️ This will only work on a local machine. If you're using Codespaces, it will disconnect. ⚠️ (y/n): ").strip().lower()
    if export == "y":
        webbrowser.open(output_file)
    else:
         print("")
    
#generate_phishing_heatmap(cur, output_file="phishing_map.html")

def cluster_phishing_sites_kmeans(cursor, n_clusters=5, output_file="phishing_clusters.html"):

    cursor.execute('''
        SELECT latitude, longitude
        FROM phishing
        WHERE latitude IS NOT NULL AND longitude IS NOT NULL
    ''')
    data = cursor.fetchall()
    coords = np.array([(lat, lon) for lat, lon in data if lat and lon])

    if len(coords) < n_clusters:
        print(f"Not enough data for {n_clusters} clusters.")
        return

    # ทำ KMeans clustering
    kmeans = KMeans(n_clusters=n_clusters, random_state=42)
    labels = kmeans.fit_predict(coords)

    m = folium.Map(location=[0, 0], zoom_start=2)

    colors = ['red', 'blue', 'green', 'purple', 'orange', 'pink', 'yellow', 'cyan', 'gray', 'black']

    for point, label in zip(coords, labels):
        folium.CircleMarker(
            location=[point[0], point[1]],
            radius=4,
            color=colors[label % len(colors)],
            fill=True,
            fill_color=colors[label % len(colors)],
            fill_opacity=0.6,
        ).add_to(m)

    for i, center in enumerate(kmeans.cluster_centers_):
        folium.Marker(
            location=[center[0], center[1]],
            icon=folium.Icon(color='white', icon='info-sign'),
            popup=f"Cluster {i}"
        ).add_to(m)

    m.save(output_file)
    print(f"Cluster map created successfully → Open file: {output_file}")
    export = input("Would you like to open the file? ⚠️ This will only work on a local machine. If you're using Codespaces, it will disconnect. ⚠️ (y/n): ").strip().lower()
    if export == "y":
        webbrowser.open(output_file)
    else:
         print("")
    
#cluster_phishing_sites_kmeans(cur, n_clusters=5)


def detect_hosting_centers_from_coordinates(cursor, min_count=5):

    cursor.execute('''
        SELECT latitude, longitude, isp, host, COUNT(*) as total
        FROM phishing
        WHERE latitude IS NOT NULL AND longitude IS NOT NULL
        GROUP BY latitude, longitude
        HAVING total >= ?
        ORDER BY total DESC
    ''', (min_count,))

    results = cursor.fetchall()

    if not results:
        print(f"No coordinates found with more than {min_count} occurrences.")
        return

    print(f"\nCoordinates with phishing found more than {min_count} times (potential suspicious hosting hubs):\n")
    for lat, lon, isp, host, total in results:
        isp = isp or "Unknown ISP"
        host = host or "Unknown Host"
        print(f"→ Lat/Lon: ({lat:.5f}, {lon:.5f}) | ISP: {isp} | Host: {host} | Count: {total}")

#detect_hosting_centers_from_coordinates(cur, min_count=5)

# ---------------------------------------------------------------------
# Network Infrastructure

def lookup_asn_owner(asn):

    try:
        response = requests.get(f"https://api.bgpview.io/asn/{asn}")
        if response.status_code == 200:
            data = response.json()
            name = data['data'].get('name', 'Unknown')
            country = data['data'].get('country_code', 'N/A')
            return f"{name} ({country})"
        else:
            return "Unable to retrieve data."
    except Exception as e:
        return f"เAn error occurred.: {e}"

def analyze_top_asns_with_owner(cursor, limit=10):

    cursor.execute('''
        SELECT asn, COUNT(*) as total
        FROM phishing
        WHERE asn IS NOT NULL AND asn != ''
        GROUP BY asn
        ORDER BY total DESC
        LIMIT ?
    ''', (limit,))

    results = cursor.fetchall()

    if not results:
        print("No related ASN data found.")
        return

    print(f"\nMost common ASN found in phishing. (Top {limit}):\n")
    print("{:<10} {:<10} {}".format("ASN", "Quantity", "Organization / Service Provider"))

    for asn, total in results:
        asn_id = str(asn).replace("AS", "") 
        owner = lookup_asn_owner(asn_id)
        print(f"{asn:<10} {total:<10} {owner}")


#analyze_top_asns_with_owner(cur, limit=10)

def analyze_top_isp(cursor, top_n=10):


    print(f"\nTop {top_n} Most common ISPs involved in phishing:\n")
    cursor.execute(f'''
        SELECT isp, COUNT(*) as total
        FROM phishing
        WHERE isp IS NOT NULL AND isp != ''
        GROUP BY isp
        ORDER BY total DESC
        LIMIT ?
    ''', (top_n,))
    
    results = cursor.fetchall()
    for idx, (isp, total) in enumerate(results, 1):
        print(f"{idx}. ISP: {isp} — Count: {total} times")
        
#analyze_top_isp(cur, top_n=10)

def analyze_top_bgp_prefixes(cursor, top_n=10):

    print(f"\nTop {top_n} Most common BGP prefixes used to host phishing sites:\n")
    cursor.execute(f'''
        SELECT bgp, COUNT(*) as total
        FROM phishing
        WHERE bgp IS NOT NULL AND bgp != ''
        GROUP BY bgp
        ORDER BY total DESC
        LIMIT ?
    ''', (top_n,))
    
    results = cursor.fetchall()
    for idx, (prefix, total) in enumerate(results, 1):
        print(f"{idx}. Prefix: {prefix} — Count: {total} times")
        
#analyze_top_bgp_prefixes(cur ,top_n=10)


def analyze_top_ips(cursor, threshold=5):

    print(f"\nIP addresses used more than {threshold} times in phishing attacks:\n")
    cursor.execute(f'''
        SELECT ip, COUNT(*) as total
        FROM phishing
        WHERE ip IS NOT NULL AND ip != ''
        GROUP BY ip
        HAVING total > ?
        ORDER BY total DESC
    ''', (threshold,))
    
    results = cursor.fetchall()
    if results:
        for idx, (ip, total) in enumerate(results, 1):
            print(f"{idx}. IP: {ip} — Number of attacks: {total} times")
    else:
        print(f"No IP addresses used more than {threshold} times.")
        
#analyze_top_ips(cur ,threshold=5)




def analyze_top_hostnames(cursor, top_n=10):

    print(f"\nTop {top_n} Most common hostnames used in phishing:\n")
    
    cursor.execute(f'''
        SELECT host, COUNT(*) as total
        FROM phishing
        WHERE host IS NOT NULL AND host != ''
        GROUP BY host
        ORDER BY total DESC
        LIMIT ?
    ''', (top_n,))
    
    results = cursor.fetchall()
    for idx, (host, total) in enumerate(results, 1):
        
        parsed_url = urlparse(f"http://{host}")
        domain_parts = parsed_url.netloc.split('.')
        root_domain = '.'.join(domain_parts[-2:]) 
        print(f"{idx}. Host: {host} (Root Domain: {root_domain}) — Count: {total} times")
        
#analyze_top_hostnames(cur, top_n=10)

def extract_keywords_from_urls_no_lib(cursor, top_n=20):

    cursor.execute("SELECT url, host FROM phishing WHERE url IS NOT NULL OR host IS NOT NULL")
    rows = cursor.fetchall()

    delimiters = ['/', '.', '-', '_', '?', '=', '&', ':']
    word_freq = {}

    def split_text(text):
        for delim in delimiters:
            text = text.replace(delim, ' ')
        return text.lower().split()

    for url, host in rows:
        combined = f"{url} {host}"
        words = split_text(combined)

        for word in words:
            if len(word) > 2 and word.isalpha():
                if word not in word_freq:
                    word_freq[word] = 1
                else:
                    word_freq[word] += 1

    # จัดเรียงคำตามจำนวนมาก -> น้อย
    sorted_words = sorted(word_freq.items(), key=lambda x: x[1], reverse=True)

    print(f"\nTop {top_n} most common words in URL/host:")
    for word, freq in sorted_words[:top_n]:
        print(f"- {word}: {freq} times")

#extract_keywords_from_urls_no_lib(cur)

# -----------------------------------------------------------------------
# time
def analyze_phishing_trends_by_quarter(cursor):

    cursor.execute("SELECT countryname, COUNT(*) as total FROM phishing WHERE countryname IS NOT NULL GROUP BY countryname")
    country_counts = cursor.fetchall()
    
    country_map = {normalize_text(row[0]): row[0] for row in country_counts}
    country_total_map = {normalize_text(row[0]): row[1] for row in country_counts}

    user_input = input("Please specify a country name or type top3, top5, top10:").strip().lower()

    if user_input.startswith("top"):
        try:
            top_n = int(user_input[3:])
        except ValueError:
            print("Invalid format, such as 'top5', 'top10")
            return
        
        top_countries = sorted(country_total_map.items(), key=lambda x: x[1], reverse=True)[:top_n]
        for norm_name, _ in top_countries:
            country = country_map[norm_name]
            print(f"\nCountry: {country}")
            cursor.execute('''
                SELECT 
                    strftime('%Y', date) AS year,
                    CAST((CAST(strftime('%m', date) AS INTEGER) - 1) / 3 + 1 AS INTEGER) AS quarter,
                    COUNT(*) as total
                FROM phishing
                WHERE countryname = ?
                GROUP BY year, quarter
                ORDER BY year, quarter
            ''', (country,))
            rows = cursor.fetchall()
            for row in rows:
                print(f"  Quarter: {row[0]}-Q{row[1]}, Counts: {row[2]}")

    else:
        norm_input = normalize_text(user_input)
        if norm_input in country_map:
            country = country_map[norm_input]
            print(f"\nDetailed quarterly trends of the country: {country}")
            cursor.execute('''
                SELECT 
                    strftime('%Y', date) AS year,
                    CAST((CAST(strftime('%m', date) AS INTEGER) - 1) / 3 + 1 AS INTEGER) AS quarter,
                    regionname,
                    regioncode,
                    COUNT(*) as total
                FROM phishing
                WHERE countryname = ?
                GROUP BY year, quarter, regionname, regioncode
                ORDER BY year, quarter
            ''', (country,))
            rows = cursor.fetchall()
            for row in rows:
                region = row[2] if row[2] else "Unknown"
                code = row[3] if row[3] else "N/A"
                print(f"  Quarter: {row[0]}-Q{row[1]}, Region: {region} ({code}), Count: {row[4]}")
        else:
            suggestions = [v for k, v in country_map.items() if k.startswith(norm_input[:3])]
            if suggestions:
                print("\nNo exact country name found. Try selecting from nearby countries.:")
                for s in suggestions:
                    print(f"- {s}")
            else:
                print("No exact or similar country found. Please try again.")

#analyze_phishing_trends_by_quarter(cur)



def compare_data_before_after_update_to_csv(cursor, output_file="compare_date.csv"):

    query = '''
    SELECT
        id,
        date,
        date_update,
        ip,
        asn,
        url,
        domain
    FROM phishing
    WHERE date != date_update
    AND julianday(date_update) - julianday(date) > 183
    ORDER BY date_update DESC
    '''

    cursor.execute(query)
    rows = cursor.fetchall()

    if rows:
        
        with open(output_file, 'w', newline='') as csvfile:
            fieldnames = ['id', 'date', 'date_update', 'ip', 'asn', 'url', 'domain']
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)

            writer.writeheader()

            for row in rows:
                id_, date, date_update, ip, asn, url, domain = row

                
                url = url if url is not None else ""
                domain = domain if domain is not None else ""

                writer.writerow({
                    'id': id_,
                    'date': date,
                    'date_update': date_update,
                    'ip': ip,
                    'asn': asn,
                    'url': url,
                    'domain': domain
                })
            print(f"Compare data before and after created successfully! Open the file {output_file} to view the result.")

    else:
        print("No data with changes between date and date_update exceeding 6 months.")
    #webbrowser.open(output_file)


#compare_data_before_after_update_to_csv(cur, output_file="before_after_update.csv")

def analyze_global_festival_phishing(cursor):

    festival_months = {
        'New Year (Jan 1)': ['01'],
        'Easter (Mar–Apr)': ['03', '04'],
        'Independence Day (Jul 4)': ['07'],
        'Halloween (Oct 31)': ['10'],
        'Thanksgiving (Nov)': ['11'],
        'Christmas (Dec 25)': ['12'],
    }

    print("Phishing Activity During Global Festival Months:\n")

    for fest_name, months in festival_months.items():
        placeholders = ', '.join('?' for _ in months)
        query = f"""
            SELECT COUNT(*) FROM phishing 
            WHERE strftime('%m', date) IN ({placeholders})
        """
        cursor.execute(query, months)
        count = cursor.fetchone()[0]
        print(f"{fest_name:<30} : {count} incidents")

#analyze_global_festival_phishing(cur)

#--------------------#
#        MAIN        #
#--------------------#

def handle_geolocation_choice(choice):
    """Handle the user's choice for the Geolocation menu."""
    if choice == 1:
        search_country_data_extended(cur)
    elif choice == 2:
        analyze_phishing_by_country(cur)
    elif choice == 3:
        get_top_phishing_cities_with_country(cur)
    elif choice == 4:
        generate_phishing_heatmap(cur)
    elif choice == 5:
        cluster_phishing_sites_kmeans(cur)
    elif choice == 6:
        detect_hosting_centers_from_coordinates(cur)
    elif choice == 7:
        show_all_countries(cur)

def handle_network_infrastructure_choice(choice):
    """Handle the user's choice for the Network Infrastructure & Web / Host menu."""
    if choice == 1:
        analyze_top_isp(cur)
    elif choice == 2:
        analyze_top_bgp_prefixes(cur)
    elif choice == 3:
        analyze_top_ips(cur)
    elif choice == 4:
        analyze_top_hostnames(cur)
    elif choice == 5:
        extract_keywords_from_urls_no_lib(cur)
        

def handle_temporal_trends_choice(choice):
    
    if choice == 1:
        analyze_phishing_trends_by_quarter(cur)
    elif choice == 2:
        compare_data_before_after_update_to_csv(cur)
    elif choice == 3:
        analyze_global_festival_phishing(cur)



# Initialize colorama
init()

def clear_screen():
    """Clear the terminal screen."""
    os.system('cls' if os.name == 'nt' else 'clear')

def banner():
    """Display the main colored ASCII banner with fish icon."""
    clear_screen()
    # Main title with shadow effect
    ascii_art = pyfiglet.figlet_format("PHISHTATS", font="slant")
    colored_art = Fore.CYAN + Style.BRIGHT + ascii_art + Style.RESET_ALL
    
    # Fish icon with bubbles
    fish_icon = Fore.BLUE + r"""
    |\   \\\\__     o
    | \_/    o \    o 
    > _   (( <_  oo  
    | / \__+___/      
    |/     |/
    """ + Style.RESET_ALL
    
    print(fish_icon + colored_art)
    print(Fore.GREEN + "API : https://phishstats.info:2096/api/phishing" + Style.RESET_ALL)
    print(Fore.YELLOW + "─" * 60 + Style.RESET_ALL + "\n")

def geolocation_banner():
    """Special banner for Geolocation menu"""
    clear_screen()
    title = pyfiglet.figlet_format("GEOLOCATION", font="small")
    colored_title = Fore.MAGENTA + Style.BRIGHT + title + Style.RESET_ALL
    
    globe_icon = Fore.CYAN + r"""
        ,-:` \;',`'-, 
      .'-;_,;  ':-;_,'.
     /;   '/    ,  _`.-\
    | '`. (`     /` ` \`|
    |:.  `\`-.   \_   / |
    |     (   `,  .`\ ;'|
     \     | .'     `-'/
      `.   ;/        .'
        `'-._____.
    """ + Style.RESET_ALL
    
    print(globe_icon + colored_title)
    print(Fore.YELLOW + "Track phishing activities across global locations" + Style.RESET_ALL)
    print(Fore.YELLOW + "─" * 60 + Style.RESET_ALL + "\n")

def network_banner():
    """Special banner for Network menu"""
    clear_screen()
    title = pyfiglet.figlet_format("NETWORK", font="small")
    colored_title = Fore.BLUE + Style.BRIGHT + title + Style.RESET_ALL
    
    network_icon = Fore.GREEN + r"""
     ( ( ( 
    ) ) ) )
   { { { {
    \ \ \ \
     ` ` ` `
    """ + Style.RESET_ALL
    
    print(network_icon + colored_title)
    print(Fore.CYAN + "Analyze infrastructure patterns of phishing sites" + Style.RESET_ALL)
    print(Fore.YELLOW + "─" * 60 + Style.RESET_ALL + "\n")

def temporal_banner():
    """Special banner for Temporal Trends menu"""
    clear_screen()
    title = pyfiglet.figlet_format("TEMPORAL", font="small")
    colored_title = Fore.RED + Style.BRIGHT + title + Style.RESET_ALL
    
    clock_icon = Fore.YELLOW + r"""
     /  12   \
    |    |    |
    |9   |   3|
    |     \   |
    |         |
     \___6___/
    """ + Style.RESET_ALL
    
    print(clock_icon + colored_title)
    print(Fore.MAGENTA + "Examine phishing trends over time" + Style.RESET_ALL)
    print(Fore.YELLOW + "─" * 60 + Style.RESET_ALL + "\n")

def show_geolocation_menu():
    """Display the Geolocation menu with styled banner."""
    geolocation_banner()
    menu = [
        "1. Find Country Details",
        "2. Phishing Statistics by Country",
        "3. Top Phishing Cities by Country",
        "4. Phishing Activity Heatmap",
        "5. Cluster Phishing Sites by Location",
        "6. Detect Hosting Centers from Coordinates",
        "7. All Countries in Database",
        "\n0. Back to main menu",
        "9. Exit"
    ]
    for item in menu:
        print(Fore.WHITE + item + Style.RESET_ALL)

def show_network_infrastructure_menu():
    """Display the Network Infrastructure menu with styled banner."""
    network_banner()
    menu = [
        "1. Top Internet Providers",
        "2. Top BGP Prefixes",
        "3. Most Used IP Addresses",
        "4. Most Common Hostnames",
        "5. Extract Keywords from URLs",
        "\n0. Back to main menu",
        "9. Exit"
    ]
    for item in menu:
        print(Fore.WHITE + item + Style.RESET_ALL)

def show_temporal_trends_menu():
    """Display the Temporal Trends menu with styled banner."""
    temporal_banner()
    menu = [
        "1. Quarterly Phishing Trends",
        "2. Compare Data Before and After Update",
        "3. Phishing Patterns During Global Festivals",
        "\n0. Back to main menu",
        "9. Exit"
    ]
    for item in menu:
        print(Fore.WHITE + item + Style.RESET_ALL)

def main():
    # Initialize database connection (you'll need to add this)
    # conn = create_db_connection()
    # cur = conn.cursor()
    
    while True:
        clear_screen()
        banner()
        print(Fore.CYAN + "Main Menu" + Style.RESET_ALL)
        menu = [
            "1. Geolocation Analysis",
            "2. Network Infrastructure Analysis",
            "3. Temporal Trends Analysis",
            "\n9. Exit Program"
        ]
        for item in menu:
            print(Fore.WHITE + item + Style.RESET_ALL)

        try:
            choice = int(input("\n" + Fore.YELLOW + "Select a category: " + Style.RESET_ALL))
        except ValueError:
            print(Fore.RED + "Invalid input, please try again." + Style.RESET_ALL)
            sleep(1)
            continue
        
        if choice == 1:
            while True:
                clear_screen()
                show_geolocation_menu()
                try:
                    geo_choice = int(input(Fore.YELLOW + "\nSelect an option: " + Style.RESET_ALL))
                except ValueError:
                    print(Fore.RED + "Invalid input" + Style.RESET_ALL)
                    sleep(1)
                    continue

                if geo_choice == 0:
                    break  
                elif geo_choice == 9:
                    print(Fore.GREEN + "Exiting program..." + Style.RESET_ALL)
                    sys.exit()
                else:
                    handle_geolocation_choice(geo_choice)  # Now properly connected
                    input(Fore.CYAN + "\nPress Enter to continue..." + Style.RESET_ALL)

        elif choice == 2:
            while True:
                clear_screen()
                show_network_infrastructure_menu()
                try:
                    net_choice = int(input(Fore.YELLOW + "\nSelect an option: " + Style.RESET_ALL))
                except ValueError:
                    print(Fore.RED + "Invalid input" + Style.RESET_ALL)
                    sleep(1)
                    continue

                if net_choice == 0:
                    break 
                elif net_choice == 9:
                    print(Fore.GREEN + "Exiting program..." + Style.RESET_ALL)
                    sys.exit()
                else:
                    handle_network_infrastructure_choice(net_choice)  # Now properly connected
                    input(Fore.CYAN + "\nPress Enter to continue..." + Style.RESET_ALL)

        elif choice == 3:
            while True:
                clear_screen()
                show_temporal_trends_menu()
                try:
                    temp_choice = int(input(Fore.YELLOW + "\nSelect an option: " + Style.RESET_ALL))
                except ValueError:
                    print(Fore.RED + "Invalid input" + Style.RESET_ALL)
                    sleep(1)
                    continue

                if temp_choice == 0:
                    break  
                elif temp_choice == 9:
                    print(Fore.GREEN + "Exiting program..." + Style.RESET_ALL)
                    sys.exit() 
                else:
                    handle_temporal_trends_choice(temp_choice)  # Now properly connected
                    input(Fore.CYAN + "\nPress Enter to continue..." + Style.RESET_ALL)

        elif choice == 9:
            print(Fore.GREEN + "Exiting program..." + Style.RESET_ALL)
            break  
        else:
            print(Fore.RED + "Invalid choice" + Style.RESET_ALL)
            sleep(1)

if __name__ == "__main__":
    main()

conn.close()
