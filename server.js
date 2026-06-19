import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import path from 'path';
import { fileURLToPath } from 'url';
import { createClient } from '@supabase/supabase-js';

dotenv.config();

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Supabase (Optional for local testing if not configured yet)
const supabaseUrl = process.env.SUPABASE_URL;
const supabaseKey = process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_ANON_KEY;
const supabase = supabaseUrl && supabaseKey ? createClient(supabaseUrl, supabaseKey) : null;

// In-memory fallback if Supabase is not configured
const inMemoryScans = new Map();

// ==========================================
// API ROUTES
// ==========================================

// 1. Receive Scan Results from CLI
app.post('/v1/scans', async (req, res) => {
  try {
    const scanData = req.body;

    // Validate basic payload
    if (!scanData.scan_id || typeof scanData.score !== 'number') {
      return res.status(400).json({ error: 'Invalid scan payload' });
    }

    if (supabase) {
      // Save to Supabase
      const { error } = await supabase
        .from('result_scan')
        .insert([{
          scan_id: scanData.scan_id,
          timestamp: scanData.timestamp,
          scanner_version: scanData.scanner_version,
          project_type: scanData.project_type,
          score: scanData.score,
          grade: scanData.grade,
          enterprise_ready: scanData.enterprise_ready,
          findings: scanData.findings,
          drift_detected: scanData.drift_detected,
          compliance_gap_count: scanData.compliance_gap_count,
          user_agent: req.headers['user-agent']
        }]);

      if (error) {
        console.error('Supabase error:', error);
        // Fallback to in-memory if DB schema isn't ready
        inMemoryScans.set(scanData.scan_id, scanData);
      }
    } else {
      // Save in-memory
      inMemoryScans.set(scanData.scan_id, scanData);
      console.log(`[Local Mode] Saved scan ${scanData.scan_id} to memory.`);
    }

    // Return the report URL
    const dashboardUrl = process.env.DELTARQ_DASHBOARD_URL || `http://localhost:${PORT}`;
    res.json({
      success: true,
      report_url: `${dashboardUrl}/report/${scanData.scan_id}`
    });

  } catch (error) {
    console.error('Failed to process scan upload:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// 2. Fetch specific scan data for the dashboard
app.get('/v1/scans/:scan_id', async (req, res) => {
  const { scan_id } = req.params;

  if (supabase) {
    const { data, error } = await supabase
      .from('result_scan')
      .select('*')
      .eq('scan_id', scan_id)
      .single();

    if (data) {
      return res.json(data);
    }
  }

  // Fallback
  const localScan = inMemoryScans.get(scan_id);
  if (localScan) {
    return res.json(localScan);
  }

  res.status(404).json({ error: 'Report not found' });
});

// 3. Lead Capture Form Submission
app.post('/v1/leads', async (req, res) => {
  try {
    const leadData = req.body;

    if (supabase) {
      const { error } = await supabase
        .from('leads_scan')
        .insert([leadData]);

      if (error) {
        console.error('Supabase error inserting lead:', error);
        return res.status(500).json({ error: 'Failed to save lead' });
      }
    } else {
      console.log('[Local Mode] Received lead:', leadData);
    }

    res.json({ success: true, message: 'Lead captured successfully' });
  } catch (error) {
    console.error('Failed to process lead:', error);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ==========================================
// FRONTEND ROUTES
// ==========================================

// Serve the report dashboard page
app.get('/report/:scan_id', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'report.html'));
});

// Default route
app.get('/', (req, res) => {
  res.send('DELTARQ API is running.');
});

// Start server
app.listen(PORT, () => {
  console.log(`
  🚀 DELTARQ Server running
  - Dashboard: http://localhost:${PORT}
  - API:       http://localhost:${PORT}/v1/scans
  `);
});
