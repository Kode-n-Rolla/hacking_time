# Stage 1: Passive JS collection from archived sources
cat targets.txt | gau | grep '\.js' | sort -u > js.txt
cat targets.txt | waybackurls | grep '\.js' | sort -u >> js.txt
sort -u js.txt > uniq_js.txt

# Stage 2: Availability check — find which JS files are currently accessible
httpx -l uniq_js.txt -mc 200 -silent > live_js.txt

# Stage 3: Active JS discovery via crawling
katana -u https://target.com -jc -o katana_js.txt

# Merge all results into one final JS list
cat live_js.txt katana_js.txt | sort -u > all_js.txt

# Stage 4: Analyze JavaScript files
# - Find endpoints and URLs
python3 linkfinder.py -i all_js.txt -o cli > links.txt

# - Extract potential secrets and API keys
python3 SecretFinder.py -i all_js.txt -o cli > secrets.txt

# - Run the all-in-one analyzer
cat all_js.txt | xargs -I{} bash -c 'echo -c "\ntarget : {}\n" && python3 lazyegg.py "{}" --js_urls --domains --ips --leaked_creds --local-storage > lazyegg_results.txt'

# Stage 5: Run nuclei exposures templates (good for secrets in JS, s3 urls etc.)
nuclei -l all_js.txt -t http/exposures/ -o nuclei_js.txt
