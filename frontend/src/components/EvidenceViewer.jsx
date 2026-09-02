import React, { useState } from 'react';
import { Terminal, Copy, Check, Image as ImageIcon, Code, ArrowDownRight } from 'lucide-react';
import './EvidenceViewer.css';

export default function EvidenceViewer({ evidenceItems = [] }) {
  const [copied, setCopied] = useState(false);

  // Group evidence by type
  const curlEvidence = evidenceItems.find((e) => e.type === 'curl');
  const reqEvidence = evidenceItems.find((e) => e.type === 'request');
  const resEvidence = evidenceItems.find((e) => e.type === 'response');
  const screenshotEvidence = evidenceItems.find((e) => e.type === 'screenshot');
  const domEvidence = evidenceItems.find((e) => e.type === 'dom_snapshot');

  // Determine initial active tab
  const availableTabs = [
    { id: 'curl', label: 'cURL Reproduction', icon: Terminal, item: curlEvidence },
    { id: 'request', label: 'HTTP Request', icon: Code, item: reqEvidence },
    { id: 'response', label: 'HTTP Response', icon: ArrowDownRight, item: resEvidence },
    { id: 'screenshot', label: 'Screenshot', icon: ImageIcon, item: screenshotEvidence },
    { id: 'dom', label: 'DOM Snapshot', icon: Code, item: domEvidence },
  ].filter((t) => t.item || t.id === 'curl');

  const [activeTab, setActiveTab] = useState(availableTabs[0]?.id || 'curl');

  const handleCopy = (text) => {
    if (!text) return;
    navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="evidence-viewer">
      <div className="evidence-tabs">
        {availableTabs.map((tab) => {
          const Icon = tab.icon;
          return (
            <button
              key={tab.id}
              className={`evidence-tab ${activeTab === tab.id ? 'active' : ''}`}
              onClick={() => setActiveTab(tab.id)}
            >
              <Icon size={15} />
              <span>{tab.label}</span>
              {tab.item && <span className="tab-indicator" />}
            </button>
          );
        })}
      </div>

      <div className="evidence-content-box">
        {/* cURL Tab */}
        {activeTab === 'curl' && (
          <div className="evidence-pane">
            <div className="pane-header">
              <span className="pane-title text-caption">Direct Reproduction Command</span>
              {curlEvidence?.content && (
                <button
                  className="btn btn-sm btn-secondary"
                  onClick={() => handleCopy(curlEvidence.content)}
                >
                  {copied ? <Check size={14} /> : <Copy size={14} />}
                  <span>{copied ? 'Copied' : 'Copy cURL'}</span>
                </button>
              )}
            </div>
            {curlEvidence?.content ? (
              <pre className="code-block text-mono">
                <code>{curlEvidence.content}</code>
              </pre>
            ) : (
              <div className="empty-pane text-muted text-body">
                No cURL command available for this candidate.
              </div>
            )}
          </div>
        )}

        {/* HTTP Request Tab */}
        {activeTab === 'request' && (
          <div className="evidence-pane">
            <div className="pane-header">
              <span className="pane-title text-caption">Injected HTTP Request</span>
              {reqEvidence?.content && (
                <button
                  className="btn btn-sm btn-secondary"
                  onClick={() => handleCopy(reqEvidence.content)}
                >
                  {copied ? <Check size={14} /> : <Copy size={14} />}
                  <span>{copied ? 'Copied' : 'Copy Request'}</span>
                </button>
              )}
            </div>
            {reqEvidence?.content ? (
              <pre className="code-block text-mono">
                <code>{reqEvidence.content}</code>
              </pre>
            ) : (
              <div className="empty-pane text-muted">No raw request recorded.</div>
            )}
          </div>
        )}

        {/* HTTP Response Tab */}
        {activeTab === 'response' && (
          <div className="evidence-pane">
            <div className="pane-header">
              <span className="pane-title text-caption">Application Differential Response</span>
            </div>
            {resEvidence?.content ? (
              <pre className="code-block text-mono">
                <code>{resEvidence.content}</code>
              </pre>
            ) : (
              <div className="empty-pane text-muted">No raw response recorded.</div>
            )}
          </div>
        )}

        {/* Screenshot Tab */}
        {activeTab === 'screenshot' && (
          <div className="evidence-pane">
            <div className="pane-header">
              <span className="pane-title text-caption">Automated Browser Capture</span>
            </div>
            {screenshotEvidence?.file_path ? (
              <div className="screenshot-container">
                <img
                  src={screenshotEvidence.file_path}
                  alt="Vulnerability Evidence Proof"
                  className="evidence-img"
                />
              </div>
            ) : screenshotEvidence?.content ? (
              <div className="screenshot-container">
                <img
                  src={`data:image/png;base64,${screenshotEvidence.content}`}
                  alt="Vulnerability Evidence Proof"
                  className="evidence-img"
                />
              </div>
            ) : (
              <div className="empty-pane text-muted">No screenshot artifact stored.</div>
            )}
          </div>
        )}

        {/* DOM Snapshot Tab */}
        {activeTab === 'dom' && (
          <div className="evidence-pane">
            <div className="pane-header">
              <span className="pane-title text-caption">DOM State Snapshot</span>
            </div>
            {domEvidence?.content ? (
              <pre className="code-block text-mono">
                <code>{domEvidence.content}</code>
              </pre>
            ) : (
              <div className="empty-pane text-muted">No DOM snapshot recorded.</div>
            )}
          </div>
        )}
      </div>
    </div>
  );
}
