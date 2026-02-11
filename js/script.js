// State Management
const state = {
    settings: {
        companyName: "My Company",
        reportTitle: "Financial Report",
        logoUrl: "",
        currency: "$",
        dateFormat: "monthly",
        wifiMachines: [] // Default machines
    },
    data: {
        revenue: [],
        opex: [],
        capex: [],
        wifiVendo: []
    },
    currentPeriod: "monthly",
    editingId: null, // Track if we are editing an entry
    wifiEditingId: null,
    wifiFilter: {
        year: new Date().getFullYear(),
        month: 'all'
    }
};

let financialChart = null;
let wifiChart = null;
let wifiChartRenderTimeout = null;

// Debounce utility to prevent rapid re-renders
function debounce(func, wait) {
    let timeout;
    return function executedFunction(...args) {
        const later = () => {
            clearTimeout(timeout);
            func(...args);
        };
        clearTimeout(timeout);
        timeout = setTimeout(later, wait);
    };
}

// Multipliers to convert ANY frequency TO Monthly
const toMonthlyMultiplier = {
    "daily": 30,
    "monthly": 1,
    "quarterly": 1/3,
    "semi-annually": 1/6,
    "annually": 1/12,
    "one-time": 0
};

// Multipliers to convert Monthly base TO View Period
const fromMonthlyMultiplier = {
    "daily": 1/30,
    "monthly": 1,
    "quarterly": 3,
    "semi-annually": 6,
    "annually": 12
};

// Authentication Check
async function checkAuthentication() {
    try {
        const response = await fetch('/api/session-check');
        const data = await response.json();
        
        if (!data.authenticated) {
            window.location.href = '/login.html';
        }
    } catch (error) {
        console.error('Authentication check failed:', error);
        window.location.href = '/login.html';
    }
}

// Logout Function
async function handleLogout() {
    if (confirm('Are you sure you want to logout?')) {
        try {
            const response = await fetch('/api/logout', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                }
            });
            
            if (response.ok) {
                window.location.href = '/login.html';
            } else {
                alert('Logout failed. Please try again.');
            }
        } catch (error) {
            console.error('Logout error:', error);
            alert('Network error during logout.');
        }
    }
}

document.addEventListener('DOMContentLoaded', () => {
    // Check authentication before initializing
    checkAuthentication();
    init();
});

async function init() {
    setupEventListeners();
    await loadInitialData();
    renderAll();
}

function setupEventListeners() {
    // Navigation
    document.querySelectorAll('.menu-item').forEach(item => {
        item.addEventListener('click', (e) => {
            const target = e.currentTarget.dataset.tab;
            switchView(target);
            document.querySelectorAll('.menu-item').forEach(i => i.classList.remove('active'));
            e.currentTarget.classList.add('active');
        });
    });

    // Time Period Selector
    document.getElementById('time-period').addEventListener('change', (e) => {
        state.currentPeriod = e.target.value;
        renderDashboard();
    });

    // Entry Form
    document.getElementById('entry-form').addEventListener('submit', handleEntrySubmit);

    // Wifi Vendo Form
    const wifiForm = document.getElementById('wifi-vendo-form');
    if(wifiForm) {
        wifiForm.addEventListener('submit', handleWifiVendoSubmit);
    }
    
    // Wifi Machine Management
    const addMachineBtn = document.getElementById('add-wifi-machine-btn');
    if(addMachineBtn) {
        addMachineBtn.addEventListener('click', handleAddWifiMachine);
    }

    // Wifi Filters with debounced rendering
    const wifiYear = document.getElementById('wifi-filter-year');
    const wifiMonth = document.getElementById('wifi-filter-month');
    
    const debouncedWifiRender = debounce(renderWifiVendoView, 150);
    
    if(wifiYear) {
        wifiYear.addEventListener('change', (e) => {
            state.wifiFilter.year = parseInt(e.target.value);
            debouncedWifiRender();
        });
    }
    if(wifiMonth) {
        wifiMonth.addEventListener('change', (e) => {
            state.wifiFilter.month = e.target.value;
            debouncedWifiRender();
        });
    }

    // Sidebar Toggle
    window.toggleSidebar = function(forceState) {
        const sidebar = document.getElementById('sidebar');
        const overlay = document.getElementById('sidebar-overlay');
        const isClosed = sidebar.classList.contains('-translate-x-full');
        
        let shouldOpen = forceState !== undefined ? forceState : isClosed;

        if (shouldOpen) {
            sidebar.classList.remove('-translate-x-full');
            overlay.classList.remove('hidden');
        } else {
            sidebar.classList.add('-translate-x-full');
            overlay.classList.add('hidden');
        }
    };


    // Settings Form
    document.getElementById('settings-form').addEventListener('submit', handleSaveSettings);

    // JSON Handling
    document.getElementById('download-data').addEventListener('click', downloadData);
    document.getElementById('upload-data').addEventListener('change', uploadData);
    document.getElementById('download-settings').addEventListener('click', downloadSettings);
    
    // Logout Button
    const logoutBtn = document.getElementById('logout-btn');
    if (logoutBtn) {
        logoutBtn.addEventListener('click', handleLogout);
    }
    
    // Change Password Form
    const changePasswordForm = document.getElementById('change-password-form');
    if (changePasswordForm) {
        changePasswordForm.addEventListener('submit', handleChangePassword);
    }
}

// Data Loading
async function loadInitialData() {
    try {
        const settingsRes = await fetch('data/settings.json');
        if (settingsRes.ok) {
            const loadedSettings = await settingsRes.json();
            state.settings = { ...state.settings, ...loadedSettings };
            // Ensure array exists
            if(!state.settings.wifiMachines) state.settings.wifiMachines = ["Vendo 1", "Vendo 2"];
        }

        const dataRes = await fetch('data/financials.json');
        if (dataRes.ok) {
            const data = await dataRes.json();
            // Assign IDs if missing
            state.data.revenue = (data.revenue || []).map(addId);
            state.data.opex = (data.opex || []).map(addId);
            state.data.capex = (data.capex || []).map(addId);
            state.data.wifiVendo = (data.wifiVendo || []).map(addId);

            // Sync used machine names to settings
            const usedNames = new Set(state.data.wifiVendo.map(i => i.machineId));
            usedNames.forEach(name => {
                if(name && !state.settings.wifiMachines.includes(name)) {
                    state.settings.wifiMachines.push(name);
                }
            });
        }
    } catch (error) {
        console.warn('Could not load JSON files, using defaults or local state.', error);
    }
    
    // Set initial UI values from settings
    updateGlobalSettingsUI();
}

function addId(item) {
    if (!item.id) item.id = Date.now().toString(36) + Math.random().toString(36).substr(2);
    return item;
}

// Logic & Calculations
function calculateTotals() {
    const periodFactor = fromMonthlyMultiplier[state.currentPeriod];

    const getPeriodValue = (items) => {
        return items.reduce((total, item) => {
            if (item.frequency === 'one-time') {
                return total + item.amount; 
            } else {
                // Convert to monthly base, then to target period
                const monthlyBase = item.amount * toMonthlyMultiplier[item.frequency];
                return total + (monthlyBase * periodFactor);
            }
        }, 0);
    };

    const totalRevenue = getPeriodValue(state.data.revenue);
    const totalOpex = getPeriodValue(state.data.opex);
    // CAPEX is usually one-time, but if recurring, handles accordingly
    const totalCapex = getPeriodValue(state.data.capex.map(i => ({...i, frequency: i.frequency || 'one-time'})));

    const netProfit = totalRevenue - totalOpex; // Standard Operating profit definition

    return { totalRevenue, totalOpex, totalCapex, netProfit };
}

// Rendering
function renderAll() {
    updateGlobalSettingsUI();
    renderDashboard();
    renderTable();
    renderWifiVendoView();
    renderWifiMachineOptions();
}

function renderWifiMachineOptions() {
    const select = document.getElementById('wifi-machine-id');
    if(!select) return;

    const currentVal = select.value;
    select.innerHTML = '';
    
    (state.settings.wifiMachines || []).forEach(name => {
        const option = document.createElement('option');
        option.value = name;
        option.textContent = name;
        select.appendChild(option);
    });

    if(currentVal && state.settings.wifiMachines.includes(currentVal)) {
        select.value = currentVal;
    }
}

function handleAddWifiMachine() {
    const name = prompt("Enter new Vendo Machine Name:");
    if(name && name.trim()) {
        const cleanName = name.trim();
        if(!state.settings.wifiMachines.includes(cleanName)) {
            state.settings.wifiMachines.push(cleanName);
            saveToServer('/save-settings', state.settings);
            renderWifiMachineOptions();
        } else {
            alert('Machine name already exists!');
        }
    }
}


function updateGlobalSettingsUI() {
    // Update Sidebar / Header
    document.getElementById('company-name').textContent = state.settings.companyName || "Company";
    document.getElementById('company-logo').src = state.settings.logoUrl;
    document.getElementById('company-logo').style.display = state.settings.logoUrl ? 'block' : 'none';
    document.getElementById('report-title').textContent = state.settings.reportTitle;
    document.getElementById('time-period').value = state.currentPeriod; 

    // Update Form Fields
    document.getElementById('set-company-name').value = state.settings.companyName;
    document.getElementById('set-report-title').value = state.settings.reportTitle;
    document.getElementById('set-logo-url').value = state.settings.logoUrl;
    document.getElementById('set-currency').value = state.settings.currency;
    
    // Re-render table and dashboard to reflect currency changes
    renderTable();
    renderDashboard();
}

let trendChart = null; // Add new chart instance variable

function renderDashboard() {
    const { totalRevenue, totalOpex, totalCapex, netProfit } = calculateTotals();
    const currency = state.settings.currency;

    // Helper to format with custom symbol
    const formatMoney = (val) => `${currency}${val.toFixed(2).replace(/\d(?=(\d{3})+\.)/g, '$&,')}`;

    document.getElementById('display-revenue').textContent = formatMoney(totalRevenue);
    document.getElementById('display-opex').textContent = formatMoney(totalOpex);
    document.getElementById('display-capex').textContent = formatMoney(totalCapex);
    document.getElementById('display-profit').textContent = formatMoney(netProfit);

    renderChart(totalRevenue, totalOpex, totalCapex, netProfit);
    renderTrendChart(); // Add trend chart call
}

function renderTrendChart() {
    const ctx = document.getElementById('trend-chart');
    if(!ctx) return;
    
    // Calculate Monthly Buckets for next 12 months
    const today = new Date();
    const labels = [];
    const profitData = [];
    
    for (let i = 0; i < 12; i++) {
        // Create a date for the 1st of each future month
        const d = new Date(today.getFullYear(), today.getMonth() + i, 1);
        const monthYearStr = d.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });
        labels.push(monthYearStr);

        // Sum for this specific month
        let monthlyRevenue = 0;
        let monthlyOpex = 0;
        let monthlyCapex = 0;

        // Check helper: Does this item apply to this month date 'd'?
        // Logic: 
        // 1. If frequency != one-time, it applies (simplified projection)
        // 2. If one-time, check if item.date matches current month/year
        
        const isMatch = (item) => {
            if (item.frequency !== 'one-time') return true;
            if (!item.date) return false; // One time without date ignored in trend? or assume immediate? user preference.
            
            // Compare YYYY-MM
            const itemDate = new Date(item.date);
            // Fix timezone offset issues roughly by using UTC or just comparing components
            return itemDate.getMonth() === d.getMonth() && itemDate.getFullYear() === d.getFullYear();
        };
        
        // Sum up
        state.data.revenue.forEach(i => { if(isMatch(i)) monthlyRevenue += i.amount; });
        state.data.opex.forEach(i => { if(isMatch(i)) monthlyOpex += i.amount; });
        state.data.capex.forEach(i => { if(isMatch(i)) monthlyCapex += i.amount; });
        
        profitData.push(monthlyRevenue - monthlyOpex - monthlyCapex);
    }

    if (trendChart) {
        trendChart.destroy();
    }

    trendChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Projected Net Profit',
                data: profitData,
                borderColor: '#3b82f6',
                backgroundColor: 'rgba(59, 130, 246, 0.1)',
                tension: 0.4,
                fill: true,
                pointBackgroundColor: '#1d4ed8'
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { labels: { color: '#cbd5e1' } }
            },
            scales: {
                y: {
                    grid: { color: '#334155' },
                    ticks: { color: '#94a3b8' }
                },
                x: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8' }
                }
            }
        }
    });
}


function renderChart(rev, opex, capex, profit) {
    const ctx = document.getElementById('financial-chart').getContext('2d');
    
    // Chart.js dark mode defaults
    Chart.defaults.color = '#94a3b8';
    Chart.defaults.borderColor = '#334155';

    if (financialChart) {
        financialChart.destroy();
    }

    financialChart = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Revenue', 'OPEX', 'CAPEX', 'Net Profit'],
            datasets: [{
                label: `Financials (${state.currentPeriod})`,
                data: [rev, opex, capex, profit],
                backgroundColor: [
                    '#10b981', // Revenue - Emerald
                    '#ef4444', // OPEX - Red
                    '#f59e0b', // CAPEX - Amber
                    '#3b82f6'  // Profit - Blue
                ],
                borderWidth: 0,
                borderRadius: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    labels: {
                        color: '#cbd5e1' 
                    }
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: '#334155'
                    }
                },
                x: {
                    grid: {
                        display: false
                    }
                }
            }
        }
    });
}

function renderTable() {
    const tbody = document.querySelector('#entries-table tbody');
    tbody.innerHTML = '';

    const allEntries = [
        ...state.data.revenue.map(i => ({...i, type: 'revenue'})),
        ...state.data.opex.map(i => ({...i, type: 'opex'})),
        ...state.data.capex.map(i => ({...i, type: 'capex'}))
    ];

    if (allEntries.length === 0) {
        tbody.innerHTML = `<tr><td colspan="5" class="p-4 text-center text-slate-500">No entries yet. Add one above.</td></tr>`;
        return;
    }

    allEntries.forEach((item) => {
        const tr = document.createElement('tr');
        tr.className = "hover:bg-slate-800/50 transition-colors border-b border-slate-700/50 last:border-0";
        tr.innerHTML = `
            <td class="p-2 sm:p-4"><span class="badge ${item.type} text-xs">${item.type.toUpperCase()}</span></td>
            <td class="p-2 sm:p-4 font-medium text-slate-200 text-xs sm:text-sm break-words">${item.name}</td>
            <td class="p-2 sm:p-4 font-mono text-slate-300 text-xs sm:text-sm whitespace-nowrap">${state.settings.currency}${item.amount.toFixed(2)}</td>
            <td class="p-2 sm:p-4 text-slate-400 text-xs sm:text-sm capitalize">
                ${item.frequency || 'N/A'}<br>
                <span class="text-xs text-slate-500">${item.date || ''}</span>
            </td>
            <td class="p-2 sm:p-4 text-center space-x-1 sm:space-x-2">
                <button class="text-blue-400 hover:text-blue-300 transition-colors text-xs sm:text-sm" onclick="editEntry('${item.type}', '${item.id}')" title="Edit">
                    <i class="fas fa-edit"></i>
                </button>
                <button class="text-red-400 hover:text-red-300 transition-colors text-xs sm:text-sm" onclick="deleteEntry('${item.type}', '${item.id}')" title="Delete">
                    <i class="fas fa-trash"></i>
                </button>
            </td>
        `;
        tbody.appendChild(tr);
    });
}

// view Switching
function switchView(viewName) {
    // Clean up charts when switching away from wifi vendo view
    if (viewName !== 'wifi-vendo' && wifiChart) {
        wifiChart.destroy();
        wifiChart = null;
    }
    
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.getElementById(`view-${viewName}`).classList.add('active');
    
    // Re-render wifi vendo view when switching to it to recreate the chart
    if (viewName === 'wifi-vendo') {
        renderWifiVendoView();
    }
}

// Actions
function handleEntrySubmit(e) {
    e.preventDefault();
    
    // Get form values
    const type = document.getElementById('entry-type').value;
    const name = document.getElementById('entry-name').value;
    const amount = parseFloat(document.getElementById('entry-amount').value);
    const frequency = document.getElementById('entry-frequency').value;
    const date = document.getElementById('entry-date').value || null;

    if (state.editingId) {
        // UPDATE Existing Entry
        updateExistingEntry(state.editingId, { name, amount, frequency, type, date }); 
    } else {
        // ADD New Entry
        const newItem = addId({ name, amount, frequency, date });
        if (type === 'revenue') state.data.revenue.push(newItem);
        if (type === 'opex') state.data.opex.push(newItem);
        if (type === 'capex') state.data.capex.push(newItem);
    }

    // Reset Form
    e.target.reset();
    document.querySelector('#entry-form button[type="submit"]').innerHTML = '<i class="fas fa-plus"></i> Add Transaction';
    document.querySelector('#entry-form button[type="submit"]').classList.remove('bg-amber-600', 'hover:bg-amber-700');
    document.querySelector('#entry-form button[type="submit"]').classList.add('btn-primary');
    state.editingId = null;

    saveToServer('/save-data', state.data); // Save changes
    renderAll();
}

function updateExistingEntry(id, newData) {
    // Find where it currently lives
    let oldType = null;
    let index = -1;

    // Search in all arrays
    ['revenue', 'opex', 'capex'].forEach(cat => {
        const idx = state.data[cat].findIndex(i => i.id === id);
        if (idx !== -1) {
            oldType = cat;
            index = idx;
        }
    });

    if (oldType) {
        // Remove from old location
        state.data[oldType].splice(index, 1);
        
        // Add to new location (which might be the same)
        const newItem = { ...newData, id: id }; // Keep same ID
        state.data[newData.type].push(newItem);
    }
}

// Global functions for HTML access
window.editEntry = function(type, id) {
    // Find item
    const item = state.data[type].find(i => i.id === id);
    if (!item) return;

    // Populate Form
    document.getElementById('entry-type').value = type;
    document.getElementById('entry-name').value = item.name;
    document.getElementById('entry-amount').value = item.amount;
    document.getElementById('entry-frequency').value = item.frequency;
    document.getElementById('entry-date').value = item.date || '';

    // Set Edit Mode
    state.editingId = id;
    
    // Change Button State
    const submitBtn = document.querySelector('#entry-form button[type="submit"]');
    submitBtn.innerHTML = '<i class="fas fa-save"></i> Update Transaction';
    submitBtn.classList.remove('btn-primary');
    submitBtn.classList.add('bg-amber-600', 'hover:bg-amber-700'); // Warning color for edit

    // Scroll to form (mobile friendly)
    document.getElementById('entry-form').scrollIntoView({ behavior: 'smooth' });
};

window.deleteEntry = function(type, id) {
    if(!confirm('Delete this entry?')) return;
    
    state.data[type] = state.data[type].filter(i => i.id !== id);
    saveToServer('/save-data', state.data); // Save changes
    renderAll();
};

function handleSaveSettings(e) {
    e.preventDefault();
    state.settings.companyName = document.getElementById('set-company-name').value;
    state.settings.reportTitle = document.getElementById('set-report-title').value;
    state.settings.logoUrl = document.getElementById('set-logo-url').value;
    state.settings.currency = document.getElementById('set-currency').value;
    
    saveToServer('/save-settings', state.settings); // Save changes

    // Force re-render of everything
    renderAll();
    
    // alert('Settings Saved! Download the JSON backup if you want to keep these changes permanently.');
}

// File I/O
function downloadObjectAsJson(exportObj, exportName) {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(exportObj, null, 2));
    const downloadAnchorNode = document.createElement('a');
    downloadAnchorNode.setAttribute("href", dataStr);
    downloadAnchorNode.setAttribute("download", exportName + ".json");
    document.body.appendChild(downloadAnchorNode);
    downloadAnchorNode.click();
    downloadAnchorNode.remove();
}

function downloadData() {
    downloadObjectAsJson(state.data, 'financial_data');
}

function downloadSettings() {
    downloadObjectAsJson(state.settings, 'settings');
}

function uploadData(event) {
    const file = event.target.files[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = function(e) {
        try {
            const json = JSON.parse(e.target.result);
            // Assign IDs if missing from imported data
            json.revenue = (json.revenue || []).map(addId);
            json.opex = (json.opex || []).map(addId);
            json.capex = (json.capex || []).map(addId);
            json.wifiVendo = (json.wifiVendo || []).map(addId);
            
            state.data = json; 
            saveToServer('/save-data', state.data); // Persist uploaded data
            renderAll();
            alert('Data Loaded and Saved Successfully!');
        } catch (err) {
            alert('Invalid JSON file');
            console.error(err);
        }
    };
    reader.readAsText(file);
}

// --- Backend Persistence Functions ---

function saveToServer(endpoint, payload) {
    const xhr = new XMLHttpRequest();
    xhr.open("POST", endpoint, true);
    xhr.setRequestHeader("Content-Type", "application/json");

    xhr.onreadystatechange = function () {
        if (xhr.readyState === 4) {
            if (xhr.status === 200) {
                try {
                    const result = JSON.parse(xhr.responseText);
                    console.log('Backend Save (AJAX):', result.message);
                } catch (e) {
                    console.warn('Backend Save (AJAX): Saved, but could not parse response.');
                }
            } else {
                console.error('Failed to save to server:', xhr.status, xhr.statusText);
                alert('Warning: Could not save changes to disk. Is the server running?');
            }
        }
    };

    xhr.send(JSON.stringify(payload));
}
// --- Wifi Vendo Features ---

function handleWifiVendoSubmit(e) {
    e.preventDefault();
    
    const id = document.getElementById('wifi-entry-id').value;
    const machineId = document.getElementById('wifi-machine-id').value;
    const date = document.getElementById('wifi-date').value;
    const income = parseFloat(document.getElementById('wifi-income').value) || 0;
    const expense = parseFloat(document.getElementById('wifi-expense').value) || 0;

    const entry = {
        id: id || Date.now().toString(36) + Math.random().toString(36).substr(2),
        machineId,
        date,
        income,
        expense
    };

    if (state.wifiEditingId) {
        state.data.wifiVendo = state.data.wifiVendo.map(item => item.id === state.wifiEditingId ? entry : item);
        state.wifiEditingId = null;
        document.querySelector('#wifi-vendo-form button[type="submit"]').innerHTML = '<i class="fas fa-plus"></i> Add Entry';
        document.getElementById('wifi-entry-id').value = '';
    } else {
        state.data.wifiVendo.push(entry);
    }
    
    // Reset form field values, but keep date for convenience maybe? No, reset for clarity.
    document.getElementById('wifi-machine-id').value = '';
    document.getElementById('wifi-income').value = '';
    document.getElementById('wifi-expense').value = '';
    // document.getElementById('wifi-date').value = ''; // Optional keep date

    saveToServer('/save-data', state.data);
    renderWifiVendoView();
}

function renderWifiVendoView() {
    const allList = state.data.wifiVendo || [];
    
    // 0. Populate Year Filter & Apply Filters
    const yearSelect = document.getElementById('wifi-filter-year');
    if(yearSelect) {
        // Find unique years
        const years = new Set(allList.map(i => new Date(i.date).getFullYear()));
        years.add(new Date().getFullYear()); // Always include current
        // Sort DESC
        const sortedYears = Array.from(years).sort((a,b) => b-a);
        
        // Preserve selection or set default
        if(yearSelect.options.length === 0) {
            sortedYears.forEach(y => {
                const opt = document.createElement('option');
                opt.value = y;
                opt.textContent = y;
                yearSelect.appendChild(opt);
            });
            yearSelect.value = state.wifiFilter.year;
        } else if (yearSelect.options.length !== sortedYears.length) {
            // Re-render if count changed (simple check)
             const current = yearSelect.value;
             yearSelect.innerHTML = '';
             sortedYears.forEach(y => {
                const opt = document.createElement('option');
                opt.value = y;
                opt.textContent = y;
                yearSelect.appendChild(opt);
            });
            yearSelect.value = current;
        }
    }

    // Filter Logic
    const filteredList = allList.filter(item => {
        const d = new Date(item.date);
        const y = d.getFullYear();
        const m = d.getMonth() + 1; // 1-12
        
        const yearMatch = y === state.wifiFilter.year;
        const monthMatch = state.wifiFilter.month === 'all' || m == state.wifiFilter.month;
        
        return yearMatch && monthMatch;
    });

    // 1. Calculate Summary (Based on FILTERED Data)
    const list = filteredList;
    const totalIncome = list.reduce((sum, item) => sum + (item.income || 0), 0);
    const totalExpense = list.reduce((sum, item) => sum + (item.expense || 0), 0);
    const netProfit = totalIncome - totalExpense;

    const currency = state.settings.currency || '$';
    
    // Check elements exist
    const elIncome = document.getElementById('wifi-total-income');
    const elExpense = document.getElementById('wifi-total-expense');
    const elProfit = document.getElementById('wifi-net-profit');

    if(elIncome) elIncome.textContent = `${currency}${totalIncome.toLocaleString(undefined, {minimumFractionDigits: 2})}`;
    if(elExpense) elExpense.textContent = `${currency}${totalExpense.toLocaleString(undefined, {minimumFractionDigits: 2})}`;
    if(elProfit) elProfit.textContent = `${currency}${netProfit.toLocaleString(undefined, {minimumFractionDigits: 2})}`;

    // 2. Render Table
    const tbody = document.querySelector('#wifi-table tbody');
    if (tbody) {
        tbody.innerHTML = '';
        // Sort by date desc
        const sortedList = [...list].sort((a, b) => new Date(b.date) - new Date(a.date));

        sortedList.forEach(item => {
            const tr = document.createElement('tr');
            tr.className = "hover:bg-slate-800/50 transition-colors";
            const net = (item.income || 0) - (item.expense || 0);

            tr.innerHTML = `
                <td class="p-2 sm:p-4 border-b border-slate-700 text-slate-300 text-xs sm:text-sm whitespace-nowrap">${item.date}</td>
                <td class="p-2 sm:p-4 border-b border-slate-700 text-white font-medium text-xs sm:text-sm break-words">${item.machineId}</td>
                <td class="p-2 sm:p-4 border-b border-slate-700 text-emerald-400 font-mono text-xs sm:text-sm whitespace-nowrap">${currency}${(item.income||0).toFixed(2)}</td>
                <td class="p-2 sm:p-4 border-b border-slate-700 text-red-400 font-mono text-xs sm:text-sm whitespace-nowrap">${currency}${(item.expense||0).toFixed(2)}</td>
                <td class="p-2 sm:p-4 border-b border-slate-700 ${net >= 0 ? 'text-blue-400' : 'text-red-400'} font-mono text-xs sm:text-sm whitespace-nowrap">${currency}${net.toFixed(2)}</td>
                <td class="p-2 sm:p-4 border-b border-slate-700 text-center">
                    <button onclick="editWifiEntry('${item.id}')" class="text-slate-400 hover:text-white mx-1 transition-colors text-xs sm:text-sm" title="Edit">
                        <i class="fas fa-edit"></i>
                    </button>
                    <button onclick="deleteWifiEntry('${item.id}')" class="text-slate-400 hover:text-red-400 mx-1 transition-colors text-xs sm:text-sm" title="Delete">
                        <i class="fas fa-trash"></i>
                    </button>
                </td>
            `;
            tbody.appendChild(tr);
        });
    }

    // 3. Render Chart
    renderWifiChart(list);
}

window.deleteWifiEntry = function(id) {
    if(!confirm('Delete this vendo entry?')) return;
    state.data.wifiVendo = state.data.wifiVendo.filter(i => i.id !== id);
    saveToServer('/save-data', state.data);
    renderWifiVendoView();
};

window.editWifiEntry = function(id) {
    const item = state.data.wifiVendo.find(i => i.id === id);
    if (!item) return;

    state.wifiEditingId = id;
    
    document.getElementById('wifi-entry-id').value = item.id;
    // ...
    const machineSelect = document.getElementById('wifi-machine-id');
    if(machineSelect) {
         machineSelect.value = item.machineId;
    }
    
    document.getElementById('wifi-date').value = item.date;
    document.getElementById('wifi-income').value = item.income;
    document.getElementById('wifi-expense').value = item.expense;

    const btn = document.querySelector('#wifi-vendo-form button[type="submit"]');
    if(btn) btn.innerHTML = '<i class="fas fa-save"></i> Update Entry';
    
    // Scroll to top
    document.getElementById('view-wifi-vendo').scrollIntoView({ behavior: 'smooth' });
};

function renderWifiChart(list) {
    const ctx = document.getElementById('wifi-chart');
    if (!ctx) return;

    // Determine view type and prepare data grouping
    const isAnnual = state.wifiFilter.month === 'all';
    const grouped = {};
    
    // Early return if no data to display
    if (!list || list.length === 0) {
        if (wifiChart) {
            wifiChart.data.labels = [];
            wifiChart.data.datasets[0].data = [];
            wifiChart.data.datasets[1].data = [];
            wifiChart.update('none'); // Update without animation
        }
        return;
    }
    
    // Limit data processing to prevent freezing
    const MAX_DATA_POINTS = 100;
    if (list.length > MAX_DATA_POINTS) {
        console.warn(`Too many data points (${list.length}). Limiting to ${MAX_DATA_POINTS}`);
        list = list.slice(0, MAX_DATA_POINTS);
    }
    
    // Group data by appropriate time period with validation
    list.forEach(item => {
        if (!item.date) return; // Skip invalid entries
        
        const d = new Date(item.date);
        if (isNaN(d.getTime())) return; // Skip invalid dates
        
        const key = isAnnual ? d.getMonth() : d.getDate();
        
        if (!grouped[key]) {
            grouped[key] = { income: 0, expense: 0 };
        }
        grouped[key].income += (item.income || 0);
        grouped[key].expense += (item.expense || 0);
    });

    // Prepare chart data based on view type
    let labels = [];
    let incomeData = [];
    let expenseData = [];

    if (isAnnual) {
        // Monthly view - show all 12 months
        const monthNames = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
        labels = monthNames;
        incomeData = monthNames.map((_, i) => grouped[i]?.income || 0);
        expenseData = monthNames.map((_, i) => grouped[i]?.expense || 0);
    } else {
        // Daily view - limit to 31 days max
        const sortedDays = Object.keys(grouped).map(Number).sort((a, b) => a - b).slice(0, 31);
        if (sortedDays.length === 0) {
            // No valid data
            labels = [];
            incomeData = [];
            expenseData = [];
        } else {
            labels = sortedDays.map(d => `Day ${d}`);
            incomeData = sortedDays.map(d => grouped[d].income);
            expenseData = sortedDays.map(d => grouped[d].expense);
        }
    }

    const chartTitle = isAnnual 
        ? `Annual Overview (${state.wifiFilter.year})` 
        : `Daily Breakdown (${state.wifiFilter.year} - Month ${state.wifiFilter.month})`;

    // Update existing chart instead of recreating to prevent memory leaks
    if (wifiChart) {
        wifiChart.data.labels = labels;
        wifiChart.data.datasets[0].data = incomeData;
        wifiChart.data.datasets[1].data = expenseData;
        wifiChart.options.plugins.title.text = chartTitle;
        wifiChart.update('none'); // Update without animation to prevent freezing
    } else {
        // Create new chart instance only if it doesn't exist
        wifiChart = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [
                    {
                        label: 'Income',
                        data: incomeData,
                        backgroundColor: 'rgba(16, 185, 129, 0.5)',
                        borderColor: '#10b981',
                        borderWidth: 1
                    },
                    {
                        label: 'Expenses',
                        data: expenseData,
                        backgroundColor: 'rgba(239, 68, 68, 0.5)',
                        borderColor: '#ef4444',
                        borderWidth: 1
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false, // Disable animations to prevent performance issues
                interaction: {
                    mode: 'index',
                    intersect: false
                },
                layout: {
                    padding: 10
                },
                elements: {
                    bar: {
                        borderWidth: 0
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        grid: { color: '#334155' },
                        ticks: { 
                            color: '#94a3b8',
                            maxTicksLimit: 8 // Limit Y-axis labels
                        }
                    },
                    x: {
                        grid: { display: false },
                        ticks: { 
                            color: '#94a3b8',
                            maxRotation: 45,
                            minRotation: 0,
                            autoSkip: true,
                            maxTicksLimit: 20 // Prevent too many X-axis labels
                        }
                    }
                },
                plugins: {
                    legend: { 
                        labels: { color: '#e2e8f0' }
                    },
                    title: {
                        display: true,
                        text: chartTitle,
                        color: '#94a3b8'
                    },
                    tooltip: {
                        enabled: true,
                        mode: 'index',
                        intersect: false
                    }
                }
            }
        });
    }
}

// Password Management Functions
function togglePasswordVisibility(inputId) {
    const input = document.getElementById(inputId);
    const icon = input.nextElementSibling.querySelector('i');
    
    if (input.type === 'password') {
        input.type = 'text';
        icon.classList.remove('fa-eye');
        icon.classList.add('fa-eye-slash');
    } else {
        input.type = 'password';
        icon.classList.remove('fa-eye-slash');
        icon.classList.add('fa-eye');
    }
}

function showPasswordAlert(message, type = 'error') {
    const container = document.getElementById('password-alert-container');
    const messageDiv = document.getElementById('password-alert-message');
    const text = document.getElementById('password-alert-text');
    
    container.classList.remove('hidden');
    text.textContent = message;
    
    // Remove all possible type classes
    messageDiv.className = 'px-4 py-3 rounded-lg flex items-center gap-3';
    
    if (type === 'error') {
        messageDiv.classList.add('bg-red-900/20', 'border', 'border-red-700/50', 'text-red-400');
        messageDiv.querySelector('i').className = 'fas fa-exclamation-circle';
    } else if (type === 'success') {
        messageDiv.classList.add('bg-green-900/20', 'border', 'border-green-700/50', 'text-green-400');
        messageDiv.querySelector('i').className = 'fas fa-check-circle';
    } else if (type === 'warning') {
        messageDiv.classList.add('bg-amber-900/20', 'border', 'border-amber-700/50', 'text-amber-400');
        messageDiv.querySelector('i').className = 'fas fa-info-circle';
    }
    
    // Auto-hide after 5 seconds
    setTimeout(() => {
        container.classList.add('hidden');
    }, 5000);
}

function validatePasswordStrength(password) {
    const errors = [];
    
    if (password.length < 8) {
        errors.push('at least 8 characters');
    }
    if (!/[A-Z]/.test(password)) {
        errors.push('an uppercase letter');
    }
    if (!/[a-z]/.test(password)) {
        errors.push('a lowercase letter');
    }
    if (!/\d/.test(password)) {
        errors.push('a number');
    }
    if (!/[!@#$%^&*(),.?":{}|<>]/.test(password)) {
        errors.push('a special character');
    }
    
    return errors;
}

async function handleChangePassword(e) {
    e.preventDefault();
    
    const currentPassword = document.getElementById('current-password').value;
    const newPassword = document.getElementById('new-password').value;
    const confirmPassword = document.getElementById('confirm-password').value;
    const submitBtn = document.getElementById('change-password-btn');
    
    // Client-side validation
    if (newPassword !== confirmPassword) {
        showPasswordAlert('New passwords do not match', 'error');
        return;
    }
    
    // Validate password strength
    const strengthErrors = validatePasswordStrength(newPassword);
    if (strengthErrors.length > 0) {
        showPasswordAlert(`Password must include ${strengthErrors.join(', ')}`, 'error');
        return;
    }
    
    if (currentPassword === newPassword) {
        showPasswordAlert('New password must be different from current password', 'error');
        return;
    }
    
    // Disable button during request
    submitBtn.disabled = true;
    submitBtn.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Updating...';
    
    try {
        const response = await fetch('/api/change-password', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                current_password: currentPassword,
                new_password: newPassword
            })
        });
        
        const data = await response.json();
        
        if (response.ok && data.success) {
            showPasswordAlert('Password changed successfully!', 'success');
            
            // Clear form
            document.getElementById('change-password-form').reset();
            
            // Optional: Auto-logout after password change
            setTimeout(() => {
                showPasswordAlert('Please login again with your new password', 'warning');
                setTimeout(() => {
                    handleLogout();
                }, 2000);
            }, 2000);
        } else {
            showPasswordAlert(data.error || 'Failed to change password', 'error');
        }
    } catch (error) {
        console.error('Change password error:', error);
        showPasswordAlert('Network error. Please try again.', 'error');
    } finally {
        // Re-enable button
        submitBtn.disabled = false;
        submitBtn.innerHTML = '<i class="fas fa-lock"></i> Update Password';
    }
}
