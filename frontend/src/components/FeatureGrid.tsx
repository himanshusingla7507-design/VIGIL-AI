const LABELS: Record<string, string> = { URLLength: 'URL length', HostnameLength: 'Hostname length', DomainLength: 'Domain length', PathLength: 'Path length', QueryLength: 'Query length', SubdomainDepth: 'Subdomain depth', NoOfSubDomain: 'Subdomain count', NoOfDigitsInURL: 'Digit count', DigitRatioInURL: 'Digit ratio', NoOfHyphenInURL: 'Hyphen count', URLEntropy: 'Entropy', IsHTTPS: 'HTTPS', IsDomainIP: 'IP address', URLPercentEncodingCount: 'Encoded characters', HasPort: 'Explicit port', QueryParameterCount: 'Query parameters', PathSegmentCount: 'Path segments' }
export function FeatureGrid({ features }: { features: Record<string, string | number> }) {
  const entries = Object.entries(features).filter(([key]) => LABELS[key])
  return <div className="feature-grid">{entries.map(([key, value]) => <div className="feature-cell" key={key}><span>{LABELS[key]}</span><code>{typeof value === 'number' && key.includes('Ratio') ? value.toFixed(3) : String(value)}</code></div>)}</div>
}
