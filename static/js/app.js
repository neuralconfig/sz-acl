// SmartZone Firewall Profile Creator - Frontend JavaScript

document.addEventListener('DOMContentLoaded', function() {
    const form = document.getElementById('profileForm');
    const submitBtn = document.getElementById('submitBtn');
    const btnText = submitBtn.querySelector('.btn-text');
    const spinner = submitBtn.querySelector('.spinner');
    const listDomainsBtn = document.getElementById('listDomainsBtn');
    const resultsSection = document.getElementById('results');
    const resultsContent = document.getElementById('resultsContent');
    
    // Handle form submission
    form.addEventListener('submit', async function(e) {
        e.preventDefault();
        
        // Validate form
        const profileName = document.getElementById('profile_name').value;
        const wildcardFile = document.getElementById('wildcard_file').files[0];
        
        if (!wildcardFile && !profileName) {
            showError('Profile name is required when not using wildcard file');
            return;
        }
        
        // Show loading state
        submitBtn.disabled = true;
        btnText.style.display = 'none';
        spinner.style.display = 'block';
        
        // Prepare form data
        const formData = new FormData(form);
        
        try {
            const response = await fetch('/api/create-profile', {
                method: 'POST',
                body: formData
            });
            
            const data = await response.json();
            
            if (response.ok) {
                showResults(data.results);
            } else {
                showError(data.error || 'An error occurred');
            }
        } catch (error) {
            showError('Network error: ' + error.message);
        } finally {
            // Reset button state
            submitBtn.disabled = false;
            btnText.style.display = 'inline';
            spinner.style.display = 'none';
        }
    });
    
    // Handle list domains button
    listDomainsBtn.addEventListener('click', async function() {
        const hostname = document.getElementById('hostname').value;
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        
        if (!hostname || !username || !password) {
            showError('Please enter hostname, username, and password first');
            return;
        }
        
        // Show loading state
        listDomainsBtn.disabled = true;
        listDomainsBtn.textContent = 'Loading...';
        
        try {
            const response = await fetch('/api/list-domains', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    hostname: hostname,
                    username: username,
                    password: password
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                showDomainModal(data.domains);
            } else {
                showError(data.error || 'Failed to list domains');
            }
        } catch (error) {
            showError('Network error: ' + error.message);
        } finally {
            // Reset button state
            listDomainsBtn.disabled = false;
            listDomainsBtn.textContent = 'List Domains';
        }
    });
    
    // Show results
    function showResults(results) {
        resultsContent.innerHTML = '';
        resultsSection.style.display = 'block';
        
        results.forEach(result => {
            const resultDiv = document.createElement('div');
            resultDiv.className = `result-item ${result.status === 'success' ? 'success' : 'error'}`;
            
            if (result.status === 'success') {
                resultDiv.innerHTML = `
                    <strong>✓ ${result.site}</strong><br>
                    Firewall Profile ID: ${result.firewall_id}<br>
                    L3 ACL Policy ID: ${result.l3_acl_id}
                `;
            } else {
                resultDiv.innerHTML = `
                    <strong>✗ ${result.site}</strong><br>
                    Error: ${result.error}
                `;
            }
            
            resultsContent.appendChild(resultDiv);
        });
        
        // Scroll to results
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }
    
    // Show error message
    function showError(message) {
        resultsContent.innerHTML = `<div class="result-item error">Error: ${message}</div>`;
        resultsSection.style.display = 'block';
        resultsSection.scrollIntoView({ behavior: 'smooth' });
    }
    
    // Show domain selection modal
    function showDomainModal(domains) {
        const modal = document.getElementById('domainModal');
        const domainList = document.getElementById('domainList');
        
        domainList.innerHTML = '';
        
        if (domains.length === 0) {
            domainList.innerHTML = '<p>No domains found</p>';
        } else {
            domains.forEach(domain => {
                const domainDiv = document.createElement('div');
                domainDiv.className = 'domain-item';
                domainDiv.textContent = domain.name;
                domainDiv.onclick = function() {
                    document.getElementById('domain').value = domain.name;
                    closeDomainModal();
                };
                domainList.appendChild(domainDiv);
            });
        }
        
        modal.style.display = 'flex';
    }
    
    // Close domain modal
    window.closeDomainModal = function() {
        document.getElementById('domainModal').style.display = 'none';
    };
    
    // Close modal on outside click
    document.getElementById('domainModal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeDomainModal();
        }
    });
    
    // Cleanup functionality
    const cleanupBtn = document.getElementById('cleanupBtn');
    const cleanupModal = document.getElementById('cleanupModal');
    const searchProfilesBtn = document.getElementById('searchProfilesBtn');
    const deleteSelectedBtn = document.getElementById('deleteSelectedBtn');
    const selectAllProfiles = document.getElementById('selectAllProfiles');
    
    // Open cleanup modal
    cleanupBtn.addEventListener('click', function() {
        cleanupModal.style.display = 'flex';
        // Reset the modal state
        document.getElementById('profilesList').style.display = 'none';
        document.getElementById('cleanupResults').style.display = 'none';
        document.getElementById('deleteSelectedBtn').style.display = 'none';
        document.getElementById('cleanupPattern').value = '';
    });
    
    // Close cleanup modal
    window.closeCleanupModal = function() {
        cleanupModal.style.display = 'none';
    };
    
    // Close modal on outside click
    cleanupModal.addEventListener('click', function(e) {
        if (e.target === this) {
            closeCleanupModal();
        }
    });
    
    // Search for profiles
    searchProfilesBtn.addEventListener('click', async function() {
        const hostname = document.getElementById('hostname').value;
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const domain = document.getElementById('domain').value;
        const pattern = document.getElementById('cleanupPattern').value;
        
        if (!hostname || !username || !password) {
            showError('Please enter hostname, username, and password first');
            return;
        }
        
        // Show loading state
        searchProfilesBtn.disabled = true;
        searchProfilesBtn.textContent = 'Searching...';
        
        try {
            const response = await fetch('/api/list-firewall-profiles', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    hostname: hostname,
                    username: username,
                    password: password,
                    domain: domain,
                    pattern: pattern
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                displayProfiles(data.profiles);
            } else {
                showError(data.error || 'Failed to list profiles');
            }
        } catch (error) {
            showError('Network error: ' + error.message);
        } finally {
            searchProfilesBtn.disabled = false;
            searchProfilesBtn.textContent = 'Search Profiles';
        }
    });
    
    // Display profiles in the list
    function displayProfiles(profiles) {
        const profilesList = document.getElementById('profilesList');
        const profilesCheckboxList = document.getElementById('profilesCheckboxList');
        
        profilesCheckboxList.innerHTML = '';
        
        if (profiles.length === 0) {
            profilesCheckboxList.innerHTML = '<p>No profiles found matching the criteria</p>';
        } else {
            profiles.forEach(profile => {
                const div = document.createElement('div');
                div.className = 'profile-checkbox';
                div.innerHTML = `
                    <input type="checkbox" id="profile_${profile.id}" value="${profile.id}" 
                           data-name="${profile.name}" data-l3-acl-id="${profile.l3AclId}">
                    <div class="profile-info">
                        <div class="profile-name">${profile.name}</div>
                        <div class="profile-details">
                            ID: ${profile.id}
                            ${profile.l3AclId ? `| L3 ACL ID: ${profile.l3AclId}` : '| No L3 ACL'}
                            ${profile.description ? `| ${profile.description}` : ''}
                        </div>
                    </div>
                `;
                profilesCheckboxList.appendChild(div);
            });
        }
        
        profilesList.style.display = 'block';
        deleteSelectedBtn.style.display = profiles.length > 0 ? 'inline-block' : 'none';
    }
    
    // Select all profiles
    selectAllProfiles.addEventListener('change', function() {
        const checkboxes = document.querySelectorAll('#profilesCheckboxList input[type="checkbox"]');
        checkboxes.forEach(cb => cb.checked = this.checked);
    });
    
    // Delete selected profiles
    deleteSelectedBtn.addEventListener('click', async function() {
        const selectedProfiles = [];
        const checkboxes = document.querySelectorAll('#profilesCheckboxList input[type="checkbox"]:checked');
        
        checkboxes.forEach(cb => {
            selectedProfiles.push({
                id: cb.value,
                name: cb.dataset.name,
                l3AclId: cb.dataset.l3AclId !== 'undefined' ? cb.dataset.l3AclId : null
            });
        });
        
        if (selectedProfiles.length === 0) {
            showError('No profiles selected');
            return;
        }
        
        if (!confirm(`Are you sure you want to delete ${selectedProfiles.length} profile(s)?`)) {
            return;
        }
        
        const hostname = document.getElementById('hostname').value;
        const username = document.getElementById('username').value;
        const password = document.getElementById('password').value;
        const deleteL3Acls = document.getElementById('deleteL3Acls').checked;
        
        // Show loading state
        deleteSelectedBtn.disabled = true;
        deleteSelectedBtn.textContent = 'Deleting...';
        
        try {
            const response = await fetch('/api/delete-firewall-profiles', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    hostname: hostname,
                    username: username,
                    password: password,
                    profiles: selectedProfiles,
                    deleteL3Acls: deleteL3Acls
                })
            });
            
            const data = await response.json();
            
            if (response.ok) {
                showCleanupResults(data.results);
                // Refresh the list
                searchProfilesBtn.click();
            } else {
                showError(data.error || 'Failed to delete profiles');
            }
        } catch (error) {
            showError('Network error: ' + error.message);
        } finally {
            deleteSelectedBtn.disabled = false;
            deleteSelectedBtn.textContent = 'Delete Selected Profiles';
        }
    });
    
    // Show cleanup results
    function showCleanupResults(results) {
        const cleanupResults = document.getElementById('cleanupResults');
        cleanupResults.innerHTML = '<h4>Deletion Results:</h4>';
        
        results.forEach(result => {
            const resultDiv = document.createElement('div');
            resultDiv.className = `result-item ${result.status === 'success' ? 'success' : 'error'}`;
            
            let message = `<strong>${result.profile}</strong>: ${result.message}`;
            if (result.l3AclStatus) {
                message += ` (L3 ACL: ${result.l3AclStatus})`;
            }
            
            resultDiv.innerHTML = message;
            cleanupResults.appendChild(resultDiv);
        });
        
        cleanupResults.style.display = 'block';
    }
    
    // File input change handlers for visual feedback
    document.getElementById('rules_file').addEventListener('change', function(e) {
        const fileName = e.target.files[0]?.name;
        if (fileName) {
            console.log('Rules file selected:', fileName);
        }
    });
    
    document.getElementById('wildcard_file').addEventListener('change', function(e) {
        const fileName = e.target.files[0]?.name;
        if (fileName) {
            console.log('Wildcard file selected:', fileName);
            // Disable profile name requirement when wildcard file is selected
            document.getElementById('profile_name').removeAttribute('required');
        } else {
            // Re-enable profile name requirement
            document.getElementById('profile_name').setAttribute('required', '');
        }
    });
});