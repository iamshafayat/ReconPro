// ======================
// 1. COMPLETE DORK DATABASE
// ======================
const dorkDatabase = {
  1: { name: "Directory Listings", dork: "intitle:index.of", category: "File Exposure", risk: "medium", description: "Find open directory listings" },
  2: { name: "Config Files", dork: "ext:xml | ext:conf | ext:cnf | ext:reg | ext:inf | ext:rdp | ext:cfg | ext:txt | ext:ora | ext:ini", category: "File Exposure", risk: "high", description: "Find exposed configuration files" },
  3: { name: "Database Files", dork: "ext:sql | ext:dbf | ext:mdb", category: "File Exposure", risk: "critical", description: "Locate database files" },
  4: { name: "Log Files", dork: "ext:log", category: "File Exposure", risk: "high", description: "Find log files" },
  5: { name: "Backup Files", dork: "ext:bkf | ext:bkp | ext:bak | ext:old | ext:backup", category: "File Exposure", risk: "high", description: "Locate backup files" },
  6: { name: "Login Pages", dork: 'intext:"login" | intitle:"login" | inurl:"login" | intext:"username" | intitle:"username" | inurl:"username" | intext:"password" | intitle:"password" | inurl:"password"', category: "Web Applications", risk: "low", description: "Find login pages" },
  7: { name: "SQL Errors", dork: 'intext:"sql syntax near" | intext:"syntax error has occurred" | intext:"incorrect syntax near" | intext:"unexpected end of SQL command" | intext:"Warning: mysql_connect()" | intext:"Warning: mysql_query()" | intext:"Warning: pg_connect()"', category: "Web Applications", risk: "high", description: "Find SQL errors" },
  8: { name: "Exposed Documents", dork: "ext:doc | ext:docx | ext:odt | ext:pdf | ext:rtf | ext:sxw | ext:psw | ext:ppt | ext:pptx | ext:pps | ext:csv", category: "File Exposure", risk: "medium", description: "Find exposed documents" },
  9: { name: "phpinfo()", dork: 'ext:php intitle:phpinfo "published by the PHP Group"', category: "Web Applications", risk: "high", description: "Find phpinfo() pages" },
  10: { name: "WordPress Sites", dork: "inurl:wp- | inurl:wp-content | inurl:plugins | inurl:uploads | inurl:themes | inurl:download", category: "CMS Vulnerabilities", risk: "medium", description: "Identify WordPress installations" },
  11: { name: "Finding Backdoors", dork: "inurl:shell | inurl:backdoor | inurl:wso | inurl:cmd | shadow | passwd | boot.ini | inurl:backdoor", category: "Web Applications", risk: "critical", description: "Locate web shells" },
  12: { name: "Install/Setup Files", dork: "inurl:readme | inurl:license | inurl:install | inurl:setup | inurl:config", category: "File Exposure", risk: "medium", description: "Find setup files" },
  13: { name: "Open Redirects", dork: "inurl:redir | inurl:url | inurl:redirect | inurl:return | inurl:src=http | inurl:r=http", category: "Web Applications", risk: "medium", description: "Find open redirects" },
  14: { name: "Apache STRUTS RCE", dork: "ext:action | ext:struts | ext:do", category: "Web Applications", risk: "critical", description: "Find Struts endpoints" },
  15: { name: "Pastebin Entries", dork: "site:pastebin.com", category: "Code Repositories", risk: "medium", description: "Search Pastebin", special: true, url: "https://www.google.com/search?q=site:pastebin.com " },
  16: { name: "LinkedIn Employees", dork: "site:linkedin.com employees", category: "Code Repositories", risk: "low", description: "Find employees", special: true, url: "https://www.google.com/search?q=site:linkedin.com employees " },
  17: { name: ".htaccess/.git", dork: 'inurl:"/phpinfo.php" | inurl:".htaccess" | inurl:"/.git" -github', category: "Code Repositories", risk: "high", description: "Find exposed files" },
  18: { name: "Subdomains", dork: "site:*.", category: "Domain Intelligence", risk: "low", description: "Find subdomains" },
  19: { name: "Sub-subdomains", dork: "site:*.*.", category: "Domain Intelligence", risk: "low", description: "Find sub-subdomains" },
  20: { name: "WordPress Files", dork: "inurl:wp-content | inurl:wp-includes", category: "CMS Vulnerabilities", risk: "medium", description: "Find WordPress files" },
  21: { name: "GitHub Search", dork: '"*."', category: "Code Repositories", risk: "medium", description: "Search GitHub", special: true, url: "https://github.com/search?q=", suffix: "&type=host" },
  22: { name: "CrossDomain Test", dork: "/crossdomain.xml", category: "Domain Intelligence", risk: "medium", description: "Check crossdomain.xml", special: true, url: "http://", suffix: "/crossdomain.xml" },
  23: { name: "ThreatCrowd", dork: "", category: "Domain Intelligence", risk: "low", description: "Check ThreatCrowd", special: true, url: "http://threatcrowd.org/domain.php?domain=" },
  24: { name: "Find SWF", dork: "+inurl: +ext:swf", category: "Flash/SWF Files", risk: "medium", description: "Find SWF files" },
  25: { name: "Find MIME-SWF", dork: "site: mime:swf", category: "Flash/SWF Files", risk: "medium", description: "Find SWF by MIME", special: true, url: "https://yandex.com/search/?text=site:", suffix: " mime:swf" },
  26: { name: "Archive SWF", dork: "", category: "Flash/SWF Files", risk: "low", description: "Find archived SWF", special: true, url: "https://web.archive.org/cdx/search?url=", suffix: "/&matchType=domain&collapse=urlkey&output=text&fl=original&filter=urlkey:.*swf&limit=100000&_=1507209148310" },
  27: { name: "Archive MIME-SWF", dork: "", category: "Flash/SWF Files", risk: "low", description: "Find archived SWF by MIME", special: true, url: "https://web.archive.org/cdx/search?url=", suffix: "/&matchType=domain&collapse=urlkey&output=text&fl=original&filter=mimetype:application/x-shockwave-flash&limit=100000&_=1507209148310" },
  28: { name: "Web Archive #1", dork: "", category: "Domain Intelligence", risk: "low", description: "Search Wayback Machine", special: true, url: "https://web.archive.org/web/*/(", suffix: ")" },
  29: { name: "Web Archive #2", dork: "", category: "Domain Intelligence", risk: "low", description: "Alternative archive search", special: true, url: "https://web.archive.org/web/*/", suffix: "/*" },
  30: { name: "Certificate Transparency", dork: "", category: "Domain Intelligence", risk: "low", description: "Check certificate logs", special: true, url: "https://crt.sh/?q=%.", suffix: "" },
  31: { name: "OpenBugBounty", dork: "", category: "Code Repositories", risk: "low", description: "Check OpenBugBounty", special: true, url: "https://www.openbugbounty.org/search/?search=", suffix: "&type=host" },
  32: { name: "Reddit Search", dork: "", category: "Code Repositories", risk: "low", description: "Search Reddit", special: true, url: "https://www.reddit.com/search/?q=", suffix: "&source=recent" },
  33: { name: "WP Config Backup", dork: "+inurl: +ext:wp- | +inurl: +ext:wp-content", category: "CMS Vulnerabilities", risk: "high", description: "Find WP config backups", special: true, url: "http://wwwb-dedup.us.archive.org:8083/cdx/search?url=", suffix: "/&matchType=domain&collapse=digest&output=text&fl=original,timestamp&filter=urlkey:.*wp[-].*&limit=1000000&xx=" },
  34: { name: "Censys IPv4", dork: "", category: "Domain Intelligence", risk: "low", description: "Search Censys IPv4", special: true, url: "https://censys.io/ipv4?q=" },
  35: { name: "Censys Domain", dork: "", category: "Domain Intelligence", risk: "low", description: "Search Censys domains", special: true, url: "https://censys.io/domain?q=" },
  36: { name: "Censys Certificates", dork: "", category: "Domain Intelligence", risk: "low", description: "Search Censys certs", special: true, url: "https://censys.io/certificates?q=" },
  37: { name: "Shodan Search", dork: "", category: "Domain Intelligence", risk: "low", description: "Search Shodan", special: true, url: "https://www.shodan.io/search?query=" },
  38: { name: "Vulnerable Servers", dork: 'inurl:"/geoserver/ows?service=wfs"', category: "Web Applications", risk: "high", description: "Find GeoServer instances" },
  39: { name: "ArcGIS REST", dork: 'intext:"ArcGIS REST Services Directory" intitle:"Folder: /"', category: "Web Applications", risk: "high", description: "Find ArcGIS endpoints" },
  40: { name: "WP PDF", dork: "ext:php intitle:\"index of /wpo_wcpdf\"", category: "CMS Vulnerabilities", risk: "medium", description: "Find WP PDF invoices" },
  41: { name: "main.yml", dork: 'intitle:"index of "main.yml"', category: "File Exposure", risk: "high", description: "Find main.yml files" },
  42: { name: "Admin Portal", dork: "inurl:/admin.aspx", category: "Web Applications", risk: "medium", description: "Find admin portals" },
  43: { name: "WP Juicy 1", dork: "inurl:/wp-content/uploads/wpo_wcpdf", category: "CMS Vulnerabilities", risk: "medium", description: "Find WP PDFs" },
  44: { name: "File Upload", dork: "inurl:uploadimage.php", category: "File Uploads", risk: "high", description: "Find upload scripts" },
  45: { name: "WP Plugin", dork: "inurl:*/wp-content/plugins/contact-form-7/", category: "CMS Vulnerabilities", risk: "medium", description: "Find CF7 installs" },
  46: { name: "conf.php", dork: "intitle:index.of conf.php", category: "File Exposure", risk: "high", description: "Find PHP configs" },
  47: { name: "Sharing API", dork: 'intitle:"Sharing API Info"', category: "Web Applications", risk: "medium", description: "Find API info" },
  48: { name: "Admin Backup", dork: 'intitle:"Index of" inurl:/backup/ "admin.zip"', category: "File Exposure", risk: "critical", description: "Find admin backups" },
  49: { name: "GitHub API", dork: 'intitle:"index of" github-api', category: "Code Repositories", risk: "medium", description: "Find GitHub API" },
  50: { name: "WP Juicy 2", dork: "inurl:wp-content/uploads/wcpa_uploads", category: "CMS Vulnerabilities", risk: "medium", description: "Find WP uploads" },
  51: { name: "Drupal Login", dork: 'inurl:user intitle:"Drupal" intext:"Log in" -"powered by"', category: "CMS Vulnerabilities", risk: "medium", description: "Find Drupal logins" },
  52: { name: "Joomla DB", dork: "inurl: /libraries/joomla/database/", category: "CMS Vulnerabilities", risk: "high", description: "Find Joomla DB" },
  53: { name: "SQL Files", dork: 'inurl:"php?sql=select" ext:php', category: "Web Applications", risk: "high", description: "Find SQL queries" },
  54: { name: "WP Config", dork: 'inurl:"wp-content" intitle:"index.of" intext:wp-config.php', category: "CMS Vulnerabilities", risk: "critical", description: "Find WP configs" },
  55: { name: "JSON-RPC", dork: 'intext:"index of" inurl:json-rpc', category: "Web Applications", risk: "medium", description: "Find JSON-RPC" },
  56: { name: "Download.php", dork: 'intitle:"index of" "download.php?file="', category: "File Uploads", risk: "high", description: "Find download scripts" },
  57: { name: "JWKS-RSA", dork: 'intext:"index of" inurl:jwks-rsa', category: "File Uploads", risk: "medium", description: "Find JWKS keys" },
  58: { name: "WP Backup", dork: 'inurl:"wp-content" intitle:"index.of" intext:backup', category: "CMS Vulnerabilities", risk: "high", description: "Find WP backups" },
  59: { name: "MySQL Config", dork: "intitle:index.of conf.mysql", category: "File Uploads", risk: "critical", description: "Find MySQL configs" },
  60: { name: "YAML Files", dork: 'intitle:"index of" "users.yml" | "admin.yml" | "config.yml"', category: "File Exposure", risk: "high", description: "Find YAML files" },
  61: { name: "Docker-Compose", dork: 'intitle:"index of" "docker-compose.yml"', category: "File Exposure", risk: "high", description: "Find docker-compose" },
  62: { name: "pom.xml", dork: 'intext:"Index of" intext:"pom.xml"', category: "File Exposure", risk: "medium", description: "Find pom.xml" },
  63: { name: "/etc", dork: 'intext:"Index of" intext:"/etc"', category: "File Exposure", risk: "critical", description: "Find /etc dirs" },
  64: { name: "SQL Directories", dork: '"sql" "parent" intitle:index.of -injection', category: "File Exposure", risk: "high", description: "Find SQL dirs" },
  65: { name: "API Endpoints", dork: 'inurl:api | site:*/rest | site:*/v1 | site:*/v2 | site:*/v3', category: "API Exposure", risk: "medium", description: "Find exposed API endpoints" },
  66: { name: "API Documentation", dork: 'inurl:apidocs | inurl:api-docs | inurl:swagger | inurl:api-explorer', category: "API Exposure", risk: "low", description: "Find API documentation portals" },
  67: { name: "Sensitive DATA Leak", dork: '"date of birth" ext:pdf', category: "Sensitive Data Exposure", risk: "critical", description: "Find documents containing personally identifiable information (PII)" },
  68: { name: "Exposed Config & Log Files", dork: "ext:log | ext:txt | ext:conf | ext:cnf | ext:ini | ext:env | ext:sh | ext:bak | ext:backup | ext:swp | ext:old | ext:~ | ext:git | ext:svn | ext:htpasswd | ext:htaccess | ext:json", category: "File Exposure", risk: "high", description: "Find exposed configuration, log, and backup files" },
  69: { name: "Security.txt Bounty", dork: 'site:*/security.txt "bounty"', category: "Domain Intelligence", risk: "low", description: "Find security.txt files mentioning bounty or vulnerability disclosure" },
  70: { name: "Security.txt", dork: 'inurl:/.well-known/security.txt', category: "Domain Intelligence", risk: "low", description: "Find standard security.txt files for vulnerability disclosure" },
  71: { name: "Disclosure Policy", dork: '"vulnerability disclosure" inurl:policy', category: "Domain Intelligence", risk: "low", description: "Find vulnerability disclosure policies" },
  72: { name: "Open S3 Buckets", dork: 'intitle:"Index of" "s3.amazonaws.com"', category: "Cloud Storage Exposure", risk: "high", description: "Find exposed Amazon S3 buckets" },
  73: { name: "Azure Blobs", dork: 'site:blob.core.windows.net "index of"', category: "Cloud Storage Exposure", risk: "high", description: "Find exposed Azure storage blobs" },
  74: { name: "Google Cloud Buckets", dork: 'site:storage.googleapis.com "index of"', category: "Cloud Storage Exposure", risk: "high", description: "Find exposed Google Cloud Storage" },
  75: { name: "Firebase DB", dork: 'inurl:firebaseio.com "authDomain"', category: "Cloud Storage Exposure", risk: "critical", description: "Find misconfigured Firebase databases" },
  76: { name: "Exposed API Keys", dork: '"api_key" ext:env | ext:json | ext:yaml', category: "Sensitive Data Exposure", risk: "critical", description: "Find leaked API keys in config files" },
  77: { name: "Bearer Tokens", dork: '"Authorization: Bearer" filetype:log', category: "Sensitive Data Exposure", risk: "critical", description: "Find exposed authentication tokens in logs" },
  78: { name: "phpMyAdmin Panels", dork: 'intitle:"phpMyAdmin" "running on"', category: "Remote Management", risk: "high", description: "Find phpMyAdmin instances" },
  79: { name: "Remote Login", dork: 'inurl:remote/login | inurl:remote/desktop', category: "Remote Management", risk: "medium", description: "Find remote access login portals" },
  80: { name: "Exposed Cameras", dork: '"Network Camera" inurl:view/view.shtml', category: "IoT Devices", risk: "high", description: "Find exposed IP cameras" }
}; // Fixed: Removed trailing comma

// ======================
// 2. HELPER FUNCTIONS (defined first)
// ======================

/**
 * Safely get data from localStorage with error handling
 */
function safeLocalStorageGet(key, defaultValue) {
  try {
    const item = localStorage.getItem(key);
    return item ? JSON.parse(item) : defaultValue;
  } catch (e) {
    console.error(`Error reading ${key} from localStorage:`, e);
    return defaultValue;
  }
}

/**
 * Safely save data to localStorage with error handling
 */
function safeLocalStorageSet(key, value) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
    return true;
  } catch (e) {
    console.error(`Error saving ${key} to localStorage:`, e);
    return false;
  }
}

/**
 * Validate that dork IDs exist in the database
 */
function validateDorkIds(ids) {
  return Array.isArray(ids) ? ids.filter(id => dorkDatabase[id]) : [];
}

/**
 * Simple HTML escape function to prevent XSS
 */
function escapeHtml(text) {
  if (!text) return '';
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

// ======================
// 3. APP STATE MANAGEMENT
// ======================
const state = {
  target: '',
  favorites: validateDorkIds(safeLocalStorageGet('favorites', [])),
  history: safeLocalStorageGet('history', []).filter(entry => entry && entry.dorkId && dorkDatabase[entry.dorkId]), // Fixed: Better validation
  activeTab: 'all',
  filters: {
    category: '',
    risk: '',
    search: ''
  },
  selectedDork: null
};

// ======================
// 4. CORE FUNCTIONS
// ======================
function buildSearchUrl(dorkId, target) {
  const dork = dorkDatabase[dorkId];
  
  if (!dork) {
    console.error(`Invalid dork ID: ${dorkId}`);
    return '#';
  }

  try {
    if (dork.special) {
      // Handle special dorks (non-Google searches)
      const baseUrl = dork.url || '';
      const encodedTarget = target ? encodeURIComponent(target) : '';
      const suffix = dork.suffix || '';
      
      return baseUrl + encodedTarget + suffix;
    }

    // Regular Google dork
    if (target) {
      return `https://www.google.com/search?q=${encodeURIComponent(`site:${target} ${dork.dork}`)}`;
    }

    return `https://www.google.com/search?q=${encodeURIComponent(dork.dork)}`;
  } catch (e) {
    console.error('Error building search URL:', e);
    return '#';
  }
}

function search(dorkId) {
  try {
    const targetInput = document.getElementById('target');
    const target = targetInput ? targetInput.value.trim() : '';
    const url = buildSearchUrl(dorkId, target);
    
    if (url === '#') {
      alert('Error building search URL. Please try again.');
      return;
    }

    // Add to history only if target exists and dork is valid
    if (target && dorkDatabase[dorkId]) {
      addToHistory(dorkId, target);
    }

    state.selectedDork = dorkId;
    updateQueryPreview();
    
    // Open search in new tab
    window.open(url, '_blank');
  } catch (e) {
    console.error('Error in search function:', e);
    alert('An error occurred while searching. Please try again.');
  }
}

function addToHistory(dorkId, target) {
  if (!dorkId || !target) return;
  
  const entry = {
    dorkId: parseInt(dorkId),
    target,
    timestamp: new Date().toISOString()
  };

  state.history.unshift(entry);
  if (state.history.length > 50) state.history.pop();

  if (safeLocalStorageSet('history', state.history)) {
    renderHistory();
  }
}

function clearHistory() {
  if (confirm('Are you sure you want to clear all history?')) {
    state.history = [];
    safeLocalStorageSet('history', []);
    renderHistory();
  }
}

function toggleFavorite(dorkId) {
  dorkId = parseInt(dorkId);
  if (!dorkDatabase[dorkId]) return;
  
  const index = state.favorites.indexOf(dorkId);
  if (index === -1) {
    state.favorites.push(dorkId);
  } else {
    state.favorites.splice(index, 1);
  }

  if (safeLocalStorageSet('favorites', state.favorites)) {
    renderDorks();
    renderFavorites();
  }
}

// ======================
// 5. RENDER FUNCTIONS
// ======================
function renderDorks() {
  const container = document.getElementById('dorksContainer');
  if (!container) return;
  
  container.innerHTML = '';

  let hasResults = false;

  Object.entries(dorkDatabase).forEach(([id, dork]) => {
    // Apply filters
    if (state.filters.category && dork.category !== state.filters.category) return;
    if (state.filters.risk && dork.risk !== state.filters.risk) return;
    if (state.filters.search &&
      !dork.name.toLowerCase().includes(state.filters.search.toLowerCase()) &&
      !dork.description.toLowerCase().includes(state.filters.search.toLowerCase())) return;

    hasResults = true;

    const card = document.createElement('div');
    card.className = 'dork-card';
    card.innerHTML = `
      <div class="dork-header">
        <div class="dork-title">${escapeHtml(dork.name)}</div>
        <button class="favorite-btn ${state.favorites.includes(parseInt(id)) ? 'active' : ''}" 
                data-id="${id}" aria-label="Toggle favorite">
          <i class="fas fa-star"></i>
        </button>
      </div>
      <div class="dork-description">${escapeHtml(dork.description)}</div>
      <div class="dork-footer">
        <span class="risk-badge risk-${escapeHtml(dork.risk)}">${escapeHtml(dork.risk.toUpperCase())}</span>
        <span>${escapeHtml(dork.category)}</span>
      </div>
    `;

    card.addEventListener('click', (e) => {
      // Don't trigger if clicking the favorite button
      if (!e.target.closest('.favorite-btn')) {
        search(id);
      }
    });
    
    container.appendChild(card);
  });

  if (!hasResults) {
    container.innerHTML = `
      <div class="empty-state">
        <i class="fas fa-search"></i>
        <p>No dorks match your filters</p>
      </div>
    `;
  }

  // Add event listeners to favorite buttons
  document.querySelectorAll('.favorite-btn').forEach(btn => {
    // Remove existing listeners to prevent duplicates (Fixed)
    btn.removeEventListener('click', handleFavoriteClick);
    btn.addEventListener('click', handleFavoriteClick);
  });
}

// Helper function for favorite button clicks (Fixed: Added this function)
function handleFavoriteClick(e) {
  e.stopPropagation();
  e.preventDefault();
  toggleFavorite(e.currentTarget.dataset.id);
}

function renderFavorites() {
  const container = document.getElementById('favoritesContainer');
  if (!container) return;
  
  container.innerHTML = '';

  if (state.favorites.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <i class="far fa-star"></i>
        <p>No favorites yet. Click the star icon on any dork to add it here.</p>
      </div>
    `;
    return;
  }

  state.favorites.forEach(id => {
    const dork = dorkDatabase[id];
    if (!dork) return;

    const card = document.createElement('div');
    card.className = 'dork-card';
    card.innerHTML = `
      <div class="dork-header">
        <div class="dork-title">${escapeHtml(dork.name)}</div>
        <button class="favorite-btn active" data-id="${id}" aria-label="Remove from favorites">
          <i class="fas fa-star"></i>
        </button>
      </div>
      <div class="dork-description">${escapeHtml(dork.description)}</div>
      <div class="dork-footer">
        <span class="risk-badge risk-${escapeHtml(dork.risk)}">${escapeHtml(dork.risk.toUpperCase())}</span>
        <span>${escapeHtml(dork.category)}</span>
      </div>
    `;

    card.addEventListener('click', (e) => {
      if (!e.target.closest('.favorite-btn')) {
        search(id);
      }
    });
    
    container.appendChild(card);
  });

  // Add event listeners to favorite buttons
  document.querySelectorAll('#favoritesContainer .favorite-btn').forEach(btn => {
    btn.removeEventListener('click', handleFavoriteClick);
    btn.addEventListener('click', handleFavoriteClick);
  });
}

function renderHistory() {
  const container = document.getElementById('historyContainer');
  if (!container) return;
  
  container.innerHTML = '';

  if (state.history.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <i class="far fa-clock"></i>
        <p>No search history yet.</p>
      </div>
    `;
    return;
  }

  // Add clear history button
  const clearButton = document.createElement('button');
  clearButton.className = 'clear-history-btn';
  clearButton.innerHTML = '<i class="fas fa-trash"></i> Clear History';
  clearButton.addEventListener('click', clearHistory);
  container.appendChild(clearButton);

  state.history.slice(0, 20).forEach(entry => {
    const dork = dorkDatabase[entry.dorkId];
    if (!dork) return;

    const card = document.createElement('div');
    card.className = 'dork-card';
    card.innerHTML = `
      <div class="dork-header">
        <div class="dork-title">${escapeHtml(dork.name)}</div>
        <small>${new Date(entry.timestamp).toLocaleString()}</small>
      </div>
      <div class="dork-description">${escapeHtml(entry.target)}</div>
      <div class="dork-footer">
        <span class="risk-badge risk-${escapeHtml(dork.risk)}">${escapeHtml(dork.risk.toUpperCase())}</span>
        <span>${escapeHtml(dork.category)}</span>
      </div>
    `;

    card.addEventListener('click', () => {
      const targetInput = document.getElementById('target');
      if (targetInput) {
        targetInput.value = entry.target;
        state.target = entry.target;
        search(entry.dorkId);
      }
    });
    
    container.appendChild(card);
  });
}

function renderCategoryOptions() {
  const select = document.getElementById('categoryFilter');
  if (!select) return;
  
  const categories = new Set();

  // Clear existing options (keep the first "All Categories" option)
  while (select.options.length > 1) {
    select.remove(1);
  }

  Object.values(dorkDatabase).forEach(dork => {
    categories.add(dork.category);
  });

  Array.from(categories).sort().forEach(category => {
    const option = document.createElement('option');
    option.value = category;
    option.textContent = category;
    select.appendChild(option);
  });
}

function updateSelectStyles() {
  const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
  const textColor = isDark ? '#ffffff' : '#212529';
  const bgColor = isDark ? 'rgba(255, 255, 255, 0.08)' : 'rgba(255, 255, 255, 0.8)';

  document.querySelectorAll('select, .search-filter').forEach(el => {
    if (el) {
      el.style.color = textColor;
      el.style.backgroundColor = bgColor;
    }
  });
}

function updateThemeIcon() {
  const icon = document.querySelector('#themeToggle i');
  if (!icon) return;
  
  const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
  icon.className = isDark ? 'fas fa-moon' : 'fas fa-sun';
}

function updateQueryPreview() {
  const preview = document.getElementById('queryPreview');
  if (!preview) return;
  
  const targetInput = document.getElementById('target');
  const target = targetInput ? targetInput.value.trim() : '';

  if (!target) {
    preview.style.display = 'none';
    return;
  }

  preview.style.display = 'block';

  if (state.selectedDork) {
    const dork = dorkDatabase[state.selectedDork];
    if (dork) {
      if (dork.special) {
        preview.textContent = `${dork.url}${target}${dork.suffix || ''}`;
      } else {
        preview.textContent = `site:${target} ${dork.dork}`;
      }
    } else {
      preview.textContent = `site:${target} [select a dork to see full query]`;
    }
  } else {
    preview.textContent = `site:${target} [select a dork to see full query]`;
  }
}

// ======================
// 6. DORK SELECTION POPUP
// ======================
let currentPreset = null;

function showDorkSelectionPopup(presetName, dorkIds) {
  const popup = document.getElementById('dorkSelectionPopup');
  const title = document.getElementById('popupTitle');
  const container = document.getElementById('dorkListContainer');
  
  if (!popup || !title || !container) {
    console.error('Popup elements not found');
    return;
  }
  
  currentPreset = { name: presetName, dorkIds };
  title.textContent = `${presetName} Dorks`;
  container.innerHTML = '';

  dorkIds.forEach(id => {
    const dork = dorkDatabase[id];
    if (!dork) return;
    
    const item = document.createElement('div');
    item.className = 'dork-item';
    item.dataset.id = id;
    item.innerHTML = `
      <div class="dork-header">
        <div class="dork-title">${escapeHtml(dork.name)}</div>
        <span class="risk-badge risk-${escapeHtml(dork.risk)}">${escapeHtml(dork.risk.toUpperCase())}</span>
      </div>
      <div class="dork-description">${escapeHtml(dork.description)}</div>
      <small>Category: ${escapeHtml(dork.category)}</small>
    `;
    
    item.addEventListener('click', (e) => {
      e.stopPropagation();
      item.classList.toggle('selected');
    });
    
    container.appendChild(item);
  });

  popup.style.display = 'flex';
}

function setupPopupListeners() {
  const cancelBtn = document.getElementById('cancelPopup');
  const confirmBtn = document.getElementById('confirmPopup');
  const popup = document.getElementById('dorkSelectionPopup');
  
  if (!cancelBtn || !confirmBtn || !popup) return;

  // Remove existing listeners to prevent duplicates
  cancelBtn.replaceWith(cancelBtn.cloneNode(true));
  confirmBtn.replaceWith(confirmBtn.cloneNode(true));
  
  // Get fresh references after cloning
  const newCancelBtn = document.getElementById('cancelPopup');
  const newConfirmBtn = document.getElementById('confirmPopup');
  
  newCancelBtn.addEventListener('click', () => {
    popup.style.display = 'none';
  });

  newConfirmBtn.addEventListener('click', () => {
    const selected = document.querySelectorAll('.dork-item.selected');
    if (selected.length === 0) {
      alert('Please select at least one dork!');
      return;
    }

    const targetInput = document.getElementById('target');
    const target = targetInput ? targetInput.value.trim() : '';
    
    if (!target) {
      alert('Please enter a target first!');
      return;
    }

    selected.forEach(item => {
      const url = buildSearchUrl(item.dataset.id, target);
      if (url !== '#') {
        window.open(url, '_blank');
      }
    });

    popup.style.display = 'none';
  });

  // Close popup when clicking outside
  popup.addEventListener('click', (e) => {
    if (e.target === popup) {
      popup.style.display = 'none';
    }
  });
}

function updatePresetButtons() {
  document.querySelectorAll('[data-preset]').forEach(btn => {
    // Remove existing listeners to prevent duplicates
    btn.removeEventListener('click', handlePresetClick);
    btn.addEventListener('click', handlePresetClick);
  });
}

function handlePresetClick(e) {
  const btn = e.currentTarget;
  const presets = {
    wordpress: [10, 20, 33, 40, 43, 45, 50, 54, 58],
    sqli: [7, 53, 64],
    subdomains: [18, 19, 30]
  };

  const presetName = btn.textContent.trim();
  const presetDorks = presets[btn.dataset.preset];
  
  if (presetDorks) {
    showDorkSelectionPopup(presetName, presetDorks);
  }
}

// ======================
// 7. EVENT HANDLERS
// ======================
function setupEventListeners() {
  // Target input
  const targetInput = document.getElementById('target');
  if (targetInput) {
    targetInput.addEventListener('input', (e) => {
      state.target = e.target.value.trim();
      updateQueryPreview();
    });
  }

  // Quick search
  const quickSearchBtn = document.getElementById('quickSearch');
  if (quickSearchBtn) {
    quickSearchBtn.addEventListener('click', () => {
      if (state.target) search(1);
    });
  }

  // Filters
  const categoryFilter = document.getElementById('categoryFilter');
  if (categoryFilter) {
    categoryFilter.addEventListener('change', (e) => {
      state.filters.category = e.target.value;
      renderDorks();
    });
  }

  const riskFilter = document.getElementById('riskFilter');
  if (riskFilter) {
    riskFilter.addEventListener('change', (e) => {
      state.filters.risk = e.target.value;
      renderDorks();
    });
  }

  const searchFilter = document.getElementById('searchFilter');
  if (searchFilter) {
    searchFilter.addEventListener('input', (e) => {
      state.filters.search = e.target.value.toLowerCase();
      renderDorks();
    });
  }

  // Tabs
  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      document.querySelectorAll('.tab-content').forEach(c => c.classList.remove('active'));

      tab.classList.add('active');
      state.activeTab = tab.dataset.tab;

      if (state.activeTab === 'all') {
        const allDorks = document.getElementById('allDorks');
        if (allDorks) allDorks.classList.add('active');
        renderDorks();
      } else if (state.activeTab === 'favorites') {
        const favoritesTab = document.getElementById('favoritesTab');
        if (favoritesTab) favoritesTab.classList.add('active');
        renderFavorites();
      } else if (state.activeTab === 'history') {
        const historyTab = document.getElementById('historyTab');
        if (historyTab) historyTab.classList.add('active');
        renderHistory();
      }
    });
  });

  // Theme toggle
  const themeToggle = document.getElementById('themeToggle');
  if (themeToggle) {
    themeToggle.addEventListener('click', () => {
      const isDark = document.documentElement.getAttribute('data-theme') !== 'light';
      document.documentElement.setAttribute('data-theme', isDark ? 'light' : 'dark');
      safeLocalStorageSet('theme', isDark ? 'light' : 'dark');
      updateThemeIcon();
      updateSelectStyles();
    });
  }

  // Keyboard shortcut (Enter key)
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Enter' && state.target) {
      const activeElement = document.activeElement;
      // Don't trigger if typing in search filter
      if (activeElement?.id !== 'searchFilter' && activeElement?.id !== 'target') {
        search(1);
      }
    }
  });
}

// ======================
// 8. INITIALIZATION
// ======================
function init() {
  try {
    // Set theme from localStorage
    const savedTheme = safeLocalStorageGet('theme', 'dark');
    if (savedTheme === 'light') {
      document.documentElement.setAttribute('data-theme', 'light');
    } else {
      document.documentElement.setAttribute('data-theme', 'dark');
    }
    
    updateThemeIcon();
    updateSelectStyles();

    // Render initial UI
    renderCategoryOptions();
    renderDorks();
    renderFavorites();
    renderHistory();
    
    // Setup event listeners
    setupEventListeners();
    setupPopupListeners();
    updatePresetButtons();
    
    console.log('Dork Search initialized successfully');
  } catch (e) {
    console.error('Error initializing app:', e);
    // Show user-friendly error message
    const container = document.querySelector('.container');
    if (container) {
      container.innerHTML = `
        <div class="error-message">
          <i class="fas fa-exclamation-triangle"></i>
          <h2>Something went wrong</h2>
          <p>Please refresh the page and try again.</p>
        </div>
      `;
    }
  }
}

// Start the app when DOM is ready
if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  // DOM is already loaded
  init();
}
