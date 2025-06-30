/**
 * Universal Bitcoin - Admin Dashboard JavaScript
 * 
 * Interactive admin interface with real-time monitoring, user management,
 * Guardian Angels control, and system administration features.
 * 
 * @author Universal Bitcoin Team
 */

class UniversalBitcoinAdmin {
  constructor() {
    this.apiBase = '/api/v1';
    this.token = localStorage.getItem('adminToken');
    this.currentUser = null;
    this.currentSection = 'overview';
    this.refreshInterval = null;
    this.charts = {};
    
    this.init();
  }
  
  /**
   * Initialize the admin dashboard
   */
  async init() {
    this.showLoading();
    
    // Check authentication
    if (this.token) {
      const isValid = await this.validateToken();
      if (isValid) {
        await this.showDashboard();
      } else {
        // Clear invalid token
        localStorage.removeItem('adminToken');
        localStorage.removeItem('adminUser');
        this.token = null;
        this.showLogin();
      }
    } else {
      this.showLogin();
    }
    
    this.setupEventListeners();
    this.hideLoading();
  }
  
  /**
   * Setup all event listeners
   */
  setupEventListeners() {
    // Login form
    const loginForm = document.getElementById('login-form');
    if (loginForm) {
      loginForm.addEventListener('submit', this.handleLogin.bind(this));
    }
    
    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
      item.addEventListener('click', this.handleNavigation.bind(this));
    });
    
    // Logout
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', this.handleLogout.bind(this));
    }
    
    // Refresh button
    const refreshBtn = document.getElementById('refresh-btn');
    if (refreshBtn) {
      refreshBtn.addEventListener('click', this.refreshCurrentSection.bind(this));
    }
    
    // Modal controls
    this.setupModalListeners();
    
    // Form submissions
    this.setupFormListeners();
    
    // Real-time updates
    this.startRealTimeUpdates();
  }
  
  /**
   * Setup modal event listeners
   */
  setupModalListeners() {
    const overlay = document.getElementById('modal-overlay');
    const closeButtons = document.querySelectorAll('.modal-close, .modal-cancel');
    
    // Close modal on overlay click
    overlay?.addEventListener('click', (e) => {
      if (e.target === overlay) {
        this.closeModal();
      }
    });
    
    // Close modal on close button click
    closeButtons.forEach(btn => {
      btn.addEventListener('click', this.closeModal.bind(this));
    });
    
    // User creation modal
    const createUserBtn = document.getElementById('create-user-btn');
    createUserBtn?.addEventListener('click', () => {
      this.openModal('create-user-modal');
    });
    
    // Guardian consensus test modal
    const testConsensusBtn = document.getElementById('test-consensus-btn');
    testConsensusBtn?.addEventListener('click', () => {
      this.openModal('consensus-test-modal');
    });
    
    // Role change handler for Guardian ID field
    const newUserRole = document.getElementById('new-user-role');
    newUserRole?.addEventListener('change', (e) => {
      const guardianIdGroup = document.getElementById('guardian-id-group');
      guardianIdGroup.style.display = e.target.value === 'guardian' ? 'block' : 'none';
    });
  }
  
  /**
   * Setup form event listeners
   */
  setupFormListeners() {
    // Create user form
    const createUserForm = document.getElementById('create-user-form');
    createUserForm?.addEventListener('submit', this.handleCreateUser.bind(this));
    
    // Consensus test
    const runConsensusTest = document.getElementById('run-consensus-test');
    runConsensusTest?.addEventListener('click', this.handleConsensusTest.bind(this));
    
    // Maintenance mode
    const enableMaintenanceBtn = document.getElementById('enable-maintenance-btn');
    const disableMaintenanceBtn = document.getElementById('disable-maintenance-btn');
    
    enableMaintenanceBtn?.addEventListener('click', () => this.setMaintenanceMode(true));
    disableMaintenanceBtn?.addEventListener('click', () => this.setMaintenanceMode(false));
    
    // Configuration save
    const saveConfigBtn = document.getElementById('save-config-btn');
    saveConfigBtn?.addEventListener('click', this.saveConfiguration.bind(this));
  }
  
  /**
   * Start real-time updates
   */
  startRealTimeUpdates() {
    // Update every 30 seconds
    this.refreshInterval = setInterval(() => {
      if (this.currentSection === 'overview') {
        this.loadOverviewData();
      } else if (this.currentSection === 'stats') {
        this.loadStatsData();
      } else if (this.currentSection === 'guardians') {
        this.loadGuardiansData();
      }
    }, 30000);
  }
  
  /**
   * Stop real-time updates
   */
  stopRealTimeUpdates() {
    if (this.refreshInterval) {
      clearInterval(this.refreshInterval);
      this.refreshInterval = null;
    }
  }
  
  /**
   * Show loading screen
   */
  showLoading() {
    document.getElementById('loading-screen').style.display = 'flex';
  }
  
  /**
   * Hide loading screen
   */
  hideLoading() {
    document.getElementById('loading-screen').style.display = 'none';
  }
  
  /**
   * Show login screen
   */
  showLogin() {
    document.getElementById('login-screen').style.display = 'flex';
    document.getElementById('main-dashboard').style.display = 'none';
  }
  
  /**
   * Show dashboard
   */
  async showDashboard() {
    document.getElementById('login-screen').style.display = 'none';
    document.getElementById('main-dashboard').style.display = 'flex';
    
    // Load initial data
    await this.loadOverviewData();
    this.showSection('overview');
  }
  
  /**
   * Validate authentication token
   */
  async validateToken() {
    try {
      const response = await this.apiCall('/auth/verify', 'POST');
      if (response.success && response.valid) {
        this.currentUser = response.user;
        document.getElementById('current-user').textContent = this.currentUser.username || 'Admin User';
        return true;
      }
    } catch (error) {
      console.error('Token validation failed:', error);
    }
    return false;
  }
  
  /**
   * Handle login form submission
   */
  async handleLogin(e) {
    e.preventDefault();
    
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;
    const errorDiv = document.getElementById('login-error');
    
    try {
      const response = await fetch(`${this.apiBase}/auth/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          username: email,
          password: password
        })
      });

      const data = await response.json();

      if (response.ok && data.success) {
        this.token = data.token;
        this.currentUser = data.user;
        
        localStorage.setItem('adminToken', this.token);
        localStorage.setItem('adminUser', JSON.stringify(this.currentUser));
        
        await this.showDashboard();
      } else {
        this.showError(errorDiv, data.error?.message || 'Login failed. Please check your credentials.');
      }
    } catch (error) {
      console.error('Login error:', error);
      this.showError(errorDiv, 'Login failed. Please try again.');
    }
  }
  
  /**
   * Handle logout
   */
  async handleLogout() {
    try {
      // Call logout endpoint if token exists
      if (this.token) {
        await fetch(`${this.apiBase}/auth/logout`, {
          method: 'POST',
          headers: {
            'Authorization': `Bearer ${this.token}`,
            'Content-Type': 'application/json'
          }
        });
      }
    } catch (error) {
      console.error('Logout API call failed:', error);
    } finally {
      // Clear local storage and state
      localStorage.removeItem('adminToken');
      localStorage.removeItem('adminUser');
      this.token = null;
      this.currentUser = null;
      this.stopRealTimeUpdates();
      
      // Clear any cached data
      Object.keys(this.charts).forEach(key => {
        if (this.charts[key]) {
          this.charts[key].destroy();
        }
      });
      this.charts = {};
      
      this.showLogin();
    }
  }
  
  /**
   * Handle navigation between sections
   */
  handleNavigation(e) {
    e.preventDefault();
    
    const section = e.currentTarget.getAttribute('data-section');
    if (section) {
      this.showSection(section);
    }
  }
  
  /**
   * Show specific section
   */
  async showSection(sectionName) {
    // Update navigation
    document.querySelectorAll('.nav-item').forEach(item => {
      item.classList.remove('active');
    });
    document.querySelector(`[data-section="${sectionName}"]`)?.classList.add('active');
    
    // Update content
    document.querySelectorAll('.content-section').forEach(section => {
      section.classList.remove('active');
    });
    document.getElementById(`${sectionName}-section`)?.classList.add('active');
    
    // Update page title
    const titles = {
      'overview': 'Dashboard Overview',
      'stats': 'System Statistics', 
      'guardians': 'Guardian Angels',
      'users': 'User Management',
      'logs': 'System Logs',
      'config': 'Configuration',
      'maintenance': 'Maintenance Mode'
    };
    
    document.getElementById('page-title').textContent = titles[sectionName] || 'Dashboard';
    this.currentSection = sectionName;
    
    // Load section-specific data
    await this.loadSectionData(sectionName);
  }
  
  /**
   * Load data for specific section
   */
  async loadSectionData(section) {
    try {
      switch (section) {
        case 'overview':
          await this.loadOverviewData();
          break;
        case 'stats':
          await this.loadStatsData();
          break;
        case 'guardians':
          await this.loadGuardiansData();
          break;
        case 'users':
          await this.loadUsersData();
          break;
        case 'logs':
          await this.loadLogsData();
          break;
        case 'config':
          await this.loadConfigData();
          break;
        case 'maintenance':
          await this.loadMaintenanceData();
          break;
      }
    } catch (error) {
      console.error(`Failed to load ${section} data:`, error);
      this.showToast(`Failed to load ${section} data`, 'error');
    }
  }
  
  /**
   * Load overview dashboard data
   */
  async loadOverviewData() {
    try {
      // Load multiple data sources
      const [statsData, reservesData] = await Promise.all([
        this.apiCall('/admin/stats', 'GET'),
        this.apiCall('/reserves', 'GET')
      ]);
      
      if (statsData.success) {
        this.updateMetrics(statsData.data);
        this.updateActivityFeed(statsData.data);
      }
      
      if (reservesData.success) {
        this.updateReservesMetrics(reservesData.data);
      }
      
      // Update charts
      this.updateCharts();
      
    } catch (error) {
      console.error('Failed to load overview data:', error);
    }
  }
  
  /**
   * Update metrics cards
   */
  updateMetrics(data) {
    if (data.bitcoin) {
      document.getElementById('btc-reserves').textContent = `${data.bitcoin.balance} BTC`;
    }
    
    if (data.validations) {
      document.getElementById('validations-today').textContent = data.validations.today || '0';
    }
    
    // Update system status
    const statusElement = document.getElementById('system-status');
    const statusDot = document.querySelector('.status-dot');
    
    if (data.system && data.bitcoin && data.guardians) {
      const isHealthy = data.guardians.consensus_capable && data.bitcoin.balance > 0;
      
      if (isHealthy) {
        statusElement.textContent = 'System Healthy';
        statusDot.className = 'status-dot status-healthy';
      } else {
        statusElement.textContent = 'System Warning';
        statusDot.className = 'status-dot status-warning';
      }
    }
  }
  
  /**
   * Update reserves-specific metrics
   */
  updateReservesMetrics(data) {
    if (data.bitcoin) {
      document.getElementById('btc-reserves').textContent = `${data.bitcoin.balance} BTC`;
    }
    
    if (data.tokens) {
      document.getElementById('token-supply').textContent = `${data.tokens.total} uBTC`;
    }
    
    if (data.ratio) {
      document.getElementById('reserve-ratio').textContent = `${data.ratio.current}%`;
    }
  }
  
  /**
   * Update activity feed
   */
  updateActivityFeed(data) {
    const feed = document.getElementById('activity-feed');
    if (!feed) return;
    
    // Sample activity data
    const activities = [
      {
        icon: 'fas fa-check-circle',
        type: 'success',
        message: 'Validation completed successfully',
        time: '2 minutes ago'
      },
      {
        icon: 'fas fa-shield-alt',
        type: 'info', 
        message: 'Guardian consensus achieved (5/5)',
        time: '5 minutes ago'
      },
      {
        icon: 'fas fa-coins',
        type: 'success',
        message: 'Reserve ratio updated: 100.2%',
        time: '15 minutes ago'
      },
      {
        icon: 'fas fa-user-plus',
        type: 'info',
        message: 'New user registration',
        time: '1 hour ago'
      }
    ];
    
    feed.innerHTML = activities.map(activity => `
      <div class="activity-item">
        <div class="activity-icon ${activity.type}">
          <i class="${activity.icon}"></i>
        </div>
        <div class="activity-content">
          <p>${activity.message}</p>
          <div class="activity-time">${activity.time}</div>
        </div>
      </div>
    `).join('');
  }
  
  /**
   * Update charts
   */
  updateCharts() {
    this.updateReserveChart();
    this.updateValidationChart();
  }
  
  /**
   * Update reserve ratio chart
   */
  updateReserveChart() {
    const canvas = document.getElementById('reserve-chart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Destroy existing chart
    if (this.charts.reserve) {
      this.charts.reserve.destroy();
    }
    
    // Generate sample data
    const labels = [];
    const data = [];
    const now = new Date();
    
    for (let i = 23; i >= 0; i--) {
      const time = new Date(now.getTime() - (i * 60 * 60 * 1000));
      labels.push(time.getHours() + ':00');
      data.push(100 + (Math.random() - 0.5) * 2); // 100% ± 1%
    }
    
    this.charts.reserve = new Chart(ctx, {
      type: 'line',
      data: {
        labels: labels,
        datasets: [{
          label: 'Reserve Ratio %',
          data: data,
          borderColor: '#f7931a',
          backgroundColor: 'rgba(247, 147, 26, 0.1)',
          borderWidth: 2,
          fill: true,
          tension: 0.4
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          }
        },
        scales: {
          y: {
            beginAtZero: false,
            min: 98,
            max: 102,
            grid: {
              color: '#404040'
            },
            ticks: {
              color: '#b3b3b3'
            }
          },
          x: {
            grid: {
              color: '#404040'
            },
            ticks: {
              color: '#b3b3b3'
            }
          }
        }
      }
    });
  }
  
  /**
   * Update validation activity chart
   */
  updateValidationChart() {
    const canvas = document.getElementById('validation-chart');
    if (!canvas) return;
    
    const ctx = canvas.getContext('2d');
    
    // Destroy existing chart
    if (this.charts.validation) {
      this.charts.validation.destroy();
    }
    
    // Generate sample data
    const labels = [];
    const data = [];
    const now = new Date();
    
    for (let i = 23; i >= 0; i--) {
      const time = new Date(now.getTime() - (i * 60 * 60 * 1000));
      labels.push(time.getHours() + ':00');
      data.push(Math.floor(Math.random() * 10) + 1); // 1-10 validations per hour
    }
    
    this.charts.validation = new Chart(ctx, {
      type: 'bar',
      data: {
        labels: labels,
        datasets: [{
          label: 'Validations',
          data: data,
          backgroundColor: '#00d084',
          borderColor: '#00f094',
          borderWidth: 1
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: {
            display: false
          }
        },
        scales: {
          y: {
            beginAtZero: true,
            grid: {
              color: '#404040'
            },
            ticks: {
              color: '#b3b3b3'
            }
          },
          x: {
            grid: {
              color: '#404040'
            },
            ticks: {
              color: '#b3b3b3'
            }
          }
        }
      }
    });
  }
  
  /**
   * Load statistics data
   */
  async loadStatsData() {
    try {
      const response = await this.apiCall('/admin/stats', 'GET');
      if (response.success) {
        this.renderStatsContent(response.data);
      }
    } catch (error) {
      console.error('Failed to load stats:', error);
    }
  }
  
  /**
   * Render statistics content
   */
  renderStatsContent(data) {
    const container = document.getElementById('stats-content');
    if (!container) return;
    
    container.innerHTML = `
      <div class="stats-grid">
        <div class="stats-card">
          <h3>System Information</h3>
          <div class="stats-list">
            <div class="stats-item">
              <span>Uptime:</span>
              <span>${this.formatUptime(data.system?.uptime || 0)}</span>
            </div>
            <div class="stats-item">
              <span>Environment:</span>
              <span>${data.system?.environment || 'Unknown'}</span>
            </div>
            <div class="stats-item">
              <span>Node Version:</span>
              <span>${data.system?.nodeVersion || 'Unknown'}</span>
            </div>
          </div>
        </div>
        
        <div class="stats-card">
          <h3>Bitcoin Network</h3>
          <div class="stats-list">
            <div class="stats-item">
              <span>Network:</span>
              <span>${data.bitcoin?.network || 'Unknown'}</span>
            </div>
            <div class="stats-item">
              <span>Balance:</span>
              <span>${data.bitcoin?.balance || '0'} BTC</span>
            </div>
            <div class="stats-item">
              <span>Address:</span>
              <span class="address">${data.bitcoin?.address || 'Not available'}</span>
            </div>
          </div>
        </div>
        
        <div class="stats-card">
          <h3>Validation Statistics</h3>
          <div class="stats-list">
            <div class="stats-item">
              <span>Total Validations:</span>
              <span>${data.validations?.total || '0'}</span>
            </div>
            <div class="stats-item">
              <span>Today:</span>
              <span>${data.validations?.today || '0'}</span>
            </div>
            <div class="stats-item">
              <span>Success Rate:</span>
              <span>${data.validations?.success_rate || '0'}%</span>
            </div>
            <div class="stats-item">
              <span>Pending:</span>
              <span>${data.validations?.pending || '0'}</span>
            </div>
          </div>
        </div>
        
        <div class="stats-card">
          <h3>Revenue</h3>
          <div class="stats-list">
            <div class="stats-item">
              <span>Total ETH:</span>
              <span>${data.revenue?.total_eth || '0'} ETH</span>
            </div>
            <div class="stats-item">
              <span>Total SOL:</span>
              <span>${data.revenue?.total_sol || '0'} SOL</span>
            </div>
            <div class="stats-item">
              <span>USD Value:</span>
              <span>$${this.formatNumber(data.revenue?.total_usd || 0)}</span>
            </div>
          </div>
        </div>
      </div>
    `;
  }
  
  /**
   * Load Guardian Angels data
   */
  async loadGuardiansData() {
    try {
      const response = await this.apiCall('/admin/guardians', 'GET');
      if (response.success) {
        this.renderGuardiansContent(response.data);
      }
    } catch (error) {
      console.error('Failed to load guardians:', error);
    }
  }
  
  /**
   * Render Guardian Angels content
   */
  renderGuardiansContent(data) {
    // Update summary
    if (data.summary) {
      document.getElementById('guardians-total').textContent = data.summary.total || '0';
      document.getElementById('guardians-online').textContent = data.summary.online || '0';
      document.getElementById('guardians-threshold').textContent = data.summary.threshold || '0';
      
      const capableElement = document.getElementById('guardians-capable');
      capableElement.textContent = data.summary.consensusCapable ? 'Yes' : 'No';
      capableElement.className = data.summary.consensusCapable ? 'status-positive' : 'status-negative';
    }
    
    // Render guardian grid
    const grid = document.getElementById('guardians-grid');
    if (grid && data.guardians) {
      grid.innerHTML = data.guardians.map(guardian => `
        <div class="guardian-card">
          <div class="guardian-header">
            <h4>${guardian.name}</h4>
            <span class="badge badge-${guardian.status === 'online' ? 'success' : 'warning'}">
              ${guardian.status}
            </span>
          </div>
          <div class="guardian-details">
            <div class="detail-item">
              <span>ID:</span>
              <span>${guardian.id}</span>
            </div>
            <div class="detail-item">
              <span>Location:</span>
              <span>${guardian.location}</span>
            </div>
            <div class="detail-item">
              <span>Last Seen:</span>
              <span>${this.formatRelativeTime(guardian.lastSeen)}</span>
            </div>
            <div class="detail-item">
              <span>Public Key:</span>
              <span class="text-truncate">${guardian.publicKey}</span>
            </div>
          </div>
        </div>
      `).join('');
    }
    
    // Render consensus history
    const historyContainer = document.getElementById('consensus-history');
    if (historyContainer && data.consensusHistory) {
      historyContainer.innerHTML = data.consensusHistory.map(item => `
        <div class="consensus-item">
          <div class="consensus-header">
            <span class="consensus-time">${this.formatDateTime(item.timestamp)}</span>
            <span class="badge badge-${item.result === 'success' ? 'success' : 'error'}">
              ${item.result}
            </span>
          </div>
          <div class="consensus-message">${item.message}</div>
          <div class="consensus-signatures">${item.signatures}/5 signatures</div>
        </div>
      `).join('');
    }
  }
  
  /**
   * Load users data
   */
  async loadUsersData() {
    try {
      const response = await this.apiCall('/admin/users', 'GET');
      if (response.success) {
        this.renderUsersTable(response.data.users);
      }
    } catch (error) {
      console.error('Failed to load users:', error);
    }
  }
  
  /**
   * Render users table
   */
  renderUsersTable(users) {
    const container = document.getElementById('users-table');
    if (!container) return;
    
    container.innerHTML = `
      <div class="table-container">
        <table class="table">
          <thead>
            <tr>
              <th>Name</th>
              <th>Email</th>
              <th>Role</th>
              <th>Status</th>
              <th>Created</th>
              <th>Last Login</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody>
            ${users.map(user => `
              <tr>
                <td>${user.name}</td>
                <td>${user.email}</td>
                <td>
                  <span class="badge badge-info">${user.role}</span>
                </td>
                <td>
                  <span class="badge badge-${user.active ? 'success' : 'warning'}">
                    ${user.active ? 'Active' : 'Inactive'}
                  </span>
                </td>
                <td>${this.formatDate(user.createdAt)}</td>
                <td>${this.formatDate(user.lastLogin)}</td>
                <td>
                  <button class="btn btn-sm btn-secondary" onclick="adminApp.editUser('${user.id}')">
                    <i class="fas fa-edit"></i>
                  </button>
                  <button class="btn btn-sm btn-danger" onclick="adminApp.deleteUser('${user.id}')">
                    <i class="fas fa-trash"></i>
                  </button>
                </td>
              </tr>
            `).join('')}
          </tbody>
        </table>
      </div>
    `;
  }
  
  /**
   * Load logs data
   */
  async loadLogsData() {
    try {
      const level = document.getElementById('logs-level-filter')?.value || '';
      const category = document.getElementById('logs-category-filter')?.value || '';
      
      const params = new URLSearchParams();
      if (level) params.append('level', level);
      if (category) params.append('category', category);
      params.append('limit', '50');
      
      const response = await this.apiCall(`/admin/logs?${params}`, 'GET');
      if (response.success) {
        this.renderLogsContent(response.data.logs);
      }
    } catch (error) {
      console.error('Failed to load logs:', error);
    }
  }
  
  /**
   * Render logs content
   */
  renderLogsContent(logs) {
    const container = document.getElementById('logs-content');
    if (!container) return;
    
    container.innerHTML = `
      <div class="logs-list">
        ${logs.map(log => `
          <div class="log-item log-${log.level}">
            <div class="log-header">
              <span class="log-timestamp">${this.formatDateTime(log.timestamp)}</span>
              <span class="badge badge-${this.getLogLevelBadge(log.level)}">${log.level}</span>
              <span class="badge badge-info">${log.category}</span>
            </div>
            <div class="log-message">${log.message}</div>
            ${log.metadata ? `
              <div class="log-metadata">
                <pre>${JSON.stringify(log.metadata, null, 2)}</pre>
              </div>
            ` : ''}
          </div>
        `).join('')}
      </div>
    `;
  }
  
  /**
   * Load configuration data
   */
  async loadConfigData() {
    try {
      const response = await this.apiCall('/admin/config', 'GET');
      if (response.success) {
        this.renderConfigContent(response.data);
      }
    } catch (error) {
      console.error('Failed to load config:', error);
    }
  }
  
  /**
   * Render configuration content
   */
  renderConfigContent(config) {
    const container = document.getElementById('config-content');
    if (!container) return;
    
    container.innerHTML = `
      <div class="config-sections">
        <div class="config-section">
          <h3>Rate Limiting</h3>
          <div class="form-group">
            <label>Global Limit (requests/hour)</label>
            <input type="number" id="config-global-limit" value="${config.rateLimit?.global?.max || 1000}">
          </div>
          <div class="form-group">
            <label>Per IP Limit (requests/hour)</label>
            <input type="number" id="config-ip-limit" value="${config.rateLimit?.perIP?.max || 100}">
          </div>
          <div class="form-group">
            <label>Validation Limit (requests/hour)</label>
            <input type="number" id="config-validation-limit" value="${config.rateLimit?.validation?.max || 10}">
          </div>
        </div>
        
        <div class="config-section">
          <h3>Guardian Angels</h3>
          <div class="form-group">
            <label>Consensus Threshold</label>
            <input type="number" id="config-guardian-threshold" value="${config.guardians?.threshold || 3}" min="1" max="5">
          </div>
          <div class="form-group">
            <label>Total Guardians</label>
            <input type="number" id="config-guardian-total" value="${config.guardians?.total || 5}" min="3" max="10">
          </div>
          <div class="form-group">
            <label>Consensus Timeout (ms)</label>
            <input type="number" id="config-guardian-timeout" value="${config.guardians?.timeout || 300000}">
          </div>
        </div>
        
        <div class="config-section">
          <h3>Blockchain Settings</h3>
          <div class="form-group">
            <label>Ethereum Minimum Payment (ETH)</label>
            <input type="text" id="config-eth-min" value="${config.blockchains?.ethereum?.minimumPayment || '0.001'}">
          </div>
          <div class="form-group">
            <label>Solana Minimum Payment (lamports)</label>
            <input type="text" id="config-sol-min" value="${config.blockchains?.solana?.minimumPayment || '10000000'}">
          </div>
        </div>
      </div>
    `;
  }
  
  /**
   * Load maintenance data
   */
  async loadMaintenanceData() {
    try {
      // Check current maintenance status
      const maintenanceData = await this.checkMaintenanceStatus();
      this.updateMaintenanceUI(maintenanceData);
    } catch (error) {
      console.error('Failed to load maintenance data:', error);
    }
  }
  
  /**
   * Handle user creation
   */
  async handleCreateUser(e) {
    e.preventDefault();
    
    const formData = {
      name: document.getElementById('new-user-name').value,
      email: document.getElementById('new-user-email').value,
      role: document.getElementById('new-user-role').value,
      guardianId: document.getElementById('new-user-guardian-id').value
    };
    
    try {
      const response = await this.apiCall('/admin/users', 'POST', formData);
      if (response.success) {
        this.showToast('User created successfully', 'success');
        this.closeModal();
        await this.loadUsersData();
        
        // Reset form
        document.getElementById('create-user-form').reset();
      }
    } catch (error) {
      this.showToast('Failed to create user', 'error');
    }
  }
  
  /**
   * Handle Guardian consensus test
   */
  async handleConsensusTest() {
    const message = document.getElementById('test-message').value;
    if (!message.trim()) {
      this.showToast('Please enter a test message', 'warning');
      return;
    }
    
    try {
      const response = await this.apiCall('/admin/guardians/test', 'POST', { message });
      if (response.success) {
        this.renderConsensusTestResults(response.data);
      }
    } catch (error) {
      this.showToast('Consensus test failed', 'error');
    }
  }
  
  /**
   * Render consensus test results
   */
  renderConsensusTestResults(results) {
    const container = document.getElementById('consensus-test-results');
    if (!container) return;
    
    container.style.display = 'block';
    container.innerHTML = `
      <h4>Test Results</h4>
      <div class="test-result-item">
        <span>Status:</span>
        <span class="badge badge-${results.success ? 'success' : 'error'}">
          ${results.success ? 'Success' : 'Failed'}
        </span>
      </div>
      <div class="test-result-item">
        <span>Signatures Received:</span>
        <span>${results.signatures.received}/${results.signatures.required}</span>
      </div>
      <div class="test-result-item">
        <span>Consensus Time:</span>
        <span>${results.consensus_time}ms</span>
      </div>
      <div class="test-result-item">
        <span>Threshold Met:</span>
        <span class="badge badge-${results.signatures.threshold_met ? 'success' : 'error'}">
          ${results.signatures.threshold_met ? 'Yes' : 'No'}
        </span>
      </div>
      ${results.final_signature ? `
        <div class="test-result-item">
          <span>Final Signature:</span>
          <span class="text-truncate">${results.final_signature}</span>
        </div>
      ` : ''}
    `;
  }
  
  /**
   * Set maintenance mode
   */
  async setMaintenanceMode(enabled) {
    const message = document.getElementById('maintenance-message').value || 'System maintenance in progress';
    const duration = parseInt(document.getElementById('maintenance-duration').value) || 60;
    
    try {
      const response = await this.apiCall('/admin/maintenance', 'POST', {
        enabled,
        message,
        estimatedDuration: duration * 60 // Convert to seconds
      });
      
      if (response.success) {
        this.showToast(`Maintenance mode ${enabled ? 'enabled' : 'disabled'}`, 'success');
        this.updateMaintenanceUI(response.data);
      }
    } catch (error) {
      this.showToast('Failed to update maintenance mode', 'error');
    }
  }
  
  /**
   * Update maintenance UI
   */
  updateMaintenanceUI(data) {
    const icon = document.getElementById('maintenance-icon');
    const status = document.getElementById('maintenance-status');
    const enableBtn = document.getElementById('enable-maintenance-btn');
    const disableBtn = document.getElementById('disable-maintenance-btn');
    
    if (data.maintenanceMode) {
      icon.className = 'fas fa-circle text-warning';
      status.textContent = 'Maintenance Mode Active';
      enableBtn.style.display = 'none';
      disableBtn.style.display = 'inline-flex';
    } else {
      icon.className = 'fas fa-circle text-success';
      status.textContent = 'System Operational';
      enableBtn.style.display = 'inline-flex';
      disableBtn.style.display = 'none';
    }
  }
  
  /**
   * Save configuration
   */
  async saveConfiguration() {
    const configData = {
      rateLimit: {
        global: { max: parseInt(document.getElementById('config-global-limit').value) },
        perIP: { max: parseInt(document.getElementById('config-ip-limit').value) },
        validation: { max: parseInt(document.getElementById('config-validation-limit').value) }
      },
      guardians: {
        threshold: parseInt(document.getElementById('config-guardian-threshold').value),
        total: parseInt(document.getElementById('config-guardian-total').value),
        timeout: parseInt(document.getElementById('config-guardian-timeout').value)
      }
    };
    
    try {
      const response = await this.apiCall('/admin/config', 'PUT', configData);
      if (response.success) {
        this.showToast('Configuration saved successfully', 'success');
      }
    } catch (error) {
      this.showToast('Failed to save configuration', 'error');
    }
  }
  
  /**
   * Refresh current section
   */
  async refreshCurrentSection() {
    await this.loadSectionData(this.currentSection);
    this.showToast('Data refreshed', 'success');
  }
  
  /**
   * Open modal
   */
  openModal(modalId) {
    const overlay = document.getElementById('modal-overlay');
    const modal = document.getElementById(modalId);
    
    if (overlay && modal) {
      // Hide all modals
      document.querySelectorAll('.modal').forEach(m => m.style.display = 'none');
      
      // Show target modal
      modal.style.display = 'block';
      overlay.classList.add('active');
    }
  }
  
  /**
   * Close modal
   */
  closeModal() {
    const overlay = document.getElementById('modal-overlay');
    if (overlay) {
      overlay.classList.remove('active');
      
      // Hide all modals after transition
      setTimeout(() => {
        document.querySelectorAll('.modal').forEach(m => m.style.display = 'none');
      }, 300);
    }
  }
  
  /**
   * Make API call
   */
  async apiCall(endpoint, method = 'GET', data = null) {
    const url = `${this.apiBase}${endpoint}`;
    const options = {
      method,
      headers: {
        'Content-Type': 'application/json'
      }
    };
    
    if (this.token) {
      options.headers['Authorization'] = `Bearer ${this.token}`;
    }
    
    if (data && method !== 'GET') {
      options.body = JSON.stringify(data);
    }
    
    const response = await fetch(url, options);
    
    if (!response.ok) {
      throw new Error(`API call failed: ${response.status}`);
    }
    
    return await response.json();
  }
  
  /**
   * Check maintenance status
   */
  async checkMaintenanceStatus() {
    // This would normally call an API endpoint
    // For demo purposes, return mock data
    return {
      maintenanceMode: false,
      message: '',
      estimatedDuration: 0
    };
  }
  
  /**
   * Show toast notification
   */
  showToast(message, type = 'info') {
    // Create toast element
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.textContent = message;
    
    // Add to page
    document.body.appendChild(toast);
    
    // Animate in
    setTimeout(() => toast.classList.add('show'), 100);
    
    // Remove after delay
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => document.body.removeChild(toast), 300);
    }, 3000);
  }
  
  /**
   * Show error message
   */
  showError(element, message) {
    element.textContent = message;
    element.classList.add('show');
    
    setTimeout(() => {
      element.classList.remove('show');
    }, 5000);
  }
  
  /**
   * Utility functions
   */
  formatUptime(seconds) {
    const days = Math.floor(seconds / 86400);
    const hours = Math.floor((seconds % 86400) / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    return `${days}d ${hours}h ${minutes}m`;
  }
  
  formatNumber(num) {
    return new Intl.NumberFormat().format(num);
  }
  
  formatDate(dateString) {
    if (!dateString) return 'Never';
    return new Date(dateString).toLocaleDateString();
  }
  
  formatDateTime(dateString) {
    if (!dateString) return 'Unknown';
    return new Date(dateString).toLocaleString();
  }
  
  formatRelativeTime(dateString) {
    if (!dateString) return 'Unknown';
    const now = new Date();
    const date = new Date(dateString);
    const diff = now - date;
    
    const minutes = Math.floor(diff / 60000);
    const hours = Math.floor(diff / 3600000);
    const days = Math.floor(diff / 86400000);
    
    if (minutes < 1) return 'Just now';
    if (minutes < 60) return `${minutes}m ago`;
    if (hours < 24) return `${hours}h ago`;
    return `${days}d ago`;
  }
  
  getLogLevelBadge(level) {
    const badges = {
      'error': 'error',
      'warn': 'warning',
      'info': 'info',
      'debug': 'info'
    };
    return badges[level] || 'info';
  }
  
  /**
   * Edit user (placeholder)
   */
  editUser(userId) {
    this.showToast(`Edit user ${userId} - Feature coming soon`, 'info');
  }
  
  /**
   * Delete user (placeholder)
   */
  deleteUser(userId) {
    if (confirm('Are you sure you want to delete this user?')) {
      this.showToast(`Delete user ${userId} - Feature coming soon`, 'info');
    }
  }
}

// Initialize admin application when DOM is loaded
document.addEventListener('DOMContentLoaded', () => {
  window.adminApp = new UniversalBitcoinAdmin();
});

// Add toast styles dynamically
const toastStyles = `
  .toast {
    position: fixed;
    top: 20px;
    right: 20px;
    padding: 12px 20px;
    border-radius: 6px;
    color: white;
    font-weight: 500;
    z-index: 10000;
    transform: translateX(100%);
    transition: transform 0.3s ease;
    max-width: 300px;
  }
  
  .toast.show {
    transform: translateX(0);
  }
  
  .toast-success { background-color: #00d084; }
  .toast-error { background-color: #ff4757; }
  .toast-warning { background-color: #ffa500; }
  .toast-info { background-color: #3742fa; }
  
  .address {
    font-family: monospace;
    font-size: 0.9em;
    word-break: break-all;
  }
  
  .text-truncate {
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 200px;
  }
  
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 1.5rem;
  }
  
  .stats-card {
    background-color: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1.5rem;
  }
  
  .stats-card h3 {
    margin-bottom: 1rem;
    color: var(--text-secondary);
  }
  
  .stats-list {
    display: flex;
    flex-direction: column;
    gap: 0.75rem;
  }
  
  .stats-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.5rem 0;
    border-bottom: 1px solid var(--border-color);
  }
  
  .stats-item:last-child {
    border-bottom: none;
  }
  
  .guardian-card {
    background-color: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1rem;
  }
  
  .guardian-header {
    display: flex;
    justify-content: between;
    align-items: center;
    margin-bottom: 1rem;
  }
  
  .guardian-details {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }
  
  .detail-item {
    display: flex;
    justify-content: space-between;
    font-size: 0.875rem;
  }
  
  .logs-list {
    display: flex;
    flex-direction: column;
    gap: 1rem;
  }
  
  .log-item {
    background-color: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 6px;
    padding: 1rem;
  }
  
  .log-header {
    display: flex;
    gap: 0.5rem;
    align-items: center;
    margin-bottom: 0.5rem;
  }
  
  .log-message {
    margin-bottom: 0.5rem;
  }
  
  .log-metadata {
    background-color: var(--bg-tertiary);
    padding: 0.5rem;
    border-radius: 4px;
    font-size: 0.75rem;
  }
  
  .log-metadata pre {
    margin: 0;
    white-space: pre-wrap;
  }
  
  .config-sections {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 2rem;
  }
  
  .config-section {
    background-color: var(--bg-card);
    border: 1px solid var(--border-color);
    border-radius: 8px;
    padding: 1.5rem;
  }
  
  .config-section h3 {
    margin-bottom: 1.5rem;
    color: var(--text-secondary);
  }
  
  .test-results {
    margin-top: 1rem;
    padding: 1rem;
    background-color: var(--bg-tertiary);
    border-radius: 6px;
  }
  
  .test-result-item {
    display: flex;
    justify-content: space-between;
    margin-bottom: 0.5rem;
  }
`;

// Inject toast styles
const styleElement = document.createElement('style');
styleElement.textContent = toastStyles;
document.head.appendChild(styleElement);