async function fetchTurnCredentials() {
    try {
        const response = await fetch('https://<your turnscredserver endpoint>:<port>/credentials');

        if (!response.ok) {
            throw new Error('Network response was not ok: ' + response.statusText);
        }

        const credentials = await response.json();

        // Log the fetched TURN credentials
        console.log("Fetched TURN Credentials:", credentials);

        // Ensure window.config.p2p exists
        if (!window.config.p2p) {
            window.config.p2p = {};
        }

        // Initialize iceServers array if it doesn't exist
        if (!window.config.p2p.iceServers) {
            window.config.p2p.iceServers = [];
        }

        // Add the fetched TURN credentials to the iceServers array
        window.config.p2p.iceServers.push({
            urls: 'turns:hook.obscurenetworks.com:5349',
            username: credentials.username,
            credential: credentials.password
        });

    } catch (error) {
        console.error('Failed to fetch TURN credentials:', error);
    }
}

// Removed the automatic invocation of fetchTurnCredentials

// Fetch the TURN credentials immediately when the script is loaded
//fetchTurnCredentials();
