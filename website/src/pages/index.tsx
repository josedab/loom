import type {ReactNode} from 'react';
import {useState} from 'react';
import clsx from 'clsx';
import Link from '@docusaurus/Link';
import useDocusaurusContext from '@docusaurus/useDocusaurusContext';
import Layout from '@theme/Layout';
import Heading from '@theme/Heading';
import CodeBlock from '@theme/CodeBlock';

import styles from './index.module.css';

const features = [
  {
    title: 'WASM-First Architecture',
    icon: '🔌',
    description: 'Write plugins in Rust, Go, or TypeScript. Full Proxy-Wasm ABI support means your plugins work across Loom, Envoy, and APISIX.',
  },
  {
    title: 'Zero Dependencies',
    icon: '📦',
    description: 'Single binary deployment with embedded wazero runtime. No CGO, no databases, no external dependencies.',
  },
  {
    title: 'HTTP/3 & QUIC',
    icon: '⚡',
    description: '0-RTT connection establishment, no head-of-line blocking, and seamless connection migration for modern protocols.',
  },
  {
    title: 'AI/LLM Gateway',
    icon: '🤖',
    description: 'Multi-provider routing for OpenAI, Anthropic, and Azure. Semantic caching, token accounting, and prompt injection detection.',
  },
  {
    title: 'GraphQL Gateway',
    icon: '🔗',
    description: 'Federation, WebSocket subscriptions, automatic persisted queries, and query depth/complexity limiting.',
  },
  {
    title: 'Production Ready',
    icon: '🛡️',
    description: 'Circuit breakers, health checks, canary deployments, traffic shadowing, and distributed rate limiting.',
  },
];

const configExample = `listeners:
  - name: http
    address: ":8080"
    protocol: http

routes:
  - id: api
    path: /api/*
    upstream: backend
    plugins:
      - rate-limit
      - jwt-auth

upstreams:
  - name: backend
    endpoints:
      - "api.internal:8080"
    load_balancer: round_robin
    health_check:
      path: /health
      interval: 10s`;

const installCommand = 'go install github.com/josedab/loom/cmd/loom@latest';

function CopyButton({text}: {text: string}) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <button
      className={styles.copyButton}
      onClick={handleCopy}
      title="Copy to clipboard"
      aria-label="Copy to clipboard"
    >
      {copied ? (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <polyline points="20 6 9 17 4 12"></polyline>
        </svg>
      ) : (
        <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
          <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
          <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
        </svg>
      )}
    </button>
  );
}

function Badge({href, src, alt}: {href: string; src: string; alt: string}) {
  return (
    <a href={href} target="_blank" rel="noopener noreferrer" className={styles.badge}>
      <img src={src} alt={alt} />
    </a>
  );
}

function Badges() {
  return (
    <div className={styles.badges}>
      <Badge
        href="https://github.com/josedab/loom/blob/main/LICENSE"
        src="https://img.shields.io/badge/License-Apache_2.0-blue.svg"
        alt="License"
      />
      <Badge
        href="https://github.com/josedab/loom"
        src="https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go&logoColor=white"
        alt="Go Version"
      />
      <Badge
        href="https://github.com/josedab/loom/actions"
        src="https://img.shields.io/github/actions/workflow/status/josedab/loom/ci.yml?branch=main&label=build"
        alt="Build Status"
      />
      <Badge
        href="https://github.com/josedab/loom/releases"
        src="https://img.shields.io/github/v/release/josedab/loom?include_prereleases"
        alt="Latest Release"
      />
    </div>
  );
}

function HomepageHeader() {
  const {siteConfig} = useDocusaurusContext();
  return (
    <header className={clsx('hero hero--primary', styles.heroBanner)}>
      <div className="container">
        <div className={styles.heroContent}>
          <Badges />
          <Heading as="h1" className="hero__title">
            {siteConfig.title}
          </Heading>
          <p className="hero__subtitle">
            High-performance API Gateway with native WebAssembly plugin support.
            <br />
            Route, transform, and secure your APIs with sub-millisecond latency.
          </p>
          <div className={styles.installBox}>
            <code>{installCommand}</code>
            <CopyButton text={installCommand} />
          </div>
          <div className={styles.buttons}>
            <Link
              className="button button--primary button--lg"
              to="/docs/getting-started/quickstart">
              Get Started
            </Link>
            <Link
              className="button button--secondary button--lg"
              href="https://github.com/josedab/loom">
              GitHub
            </Link>
          </div>
        </div>
      </div>
    </header>
  );
}

function FeatureCard({title, icon, description}: {title: string; icon: string; description: string}) {
  return (
    <div className={clsx('col col--4', styles.featureCol)}>
      <div className={styles.featureCard}>
        <div className={styles.featureIcon}>{icon}</div>
        <Heading as="h3" className={styles.featureTitle}>{title}</Heading>
        <p className={styles.featureDescription}>{description}</p>
      </div>
    </div>
  );
}

function FeaturesSection() {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className={styles.sectionHeader}>
          <Heading as="h2" className={styles.sectionTitle}>
            Everything you need to run APIs at scale
          </Heading>
          <p className={styles.sectionSubtitle}>
            From basic routing to AI-powered gateways, Loom provides enterprise features without enterprise complexity.
          </p>
        </div>
        <div className="row">
          {features.map((props, idx) => (
            <FeatureCard key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}

function ConfigExample() {
  return (
    <section className={clsx(styles.section, styles.sectionAlt)}>
      <div className="container">
        <div className="row">
          <div className="col col--5">
            <Heading as="h2" className={styles.sectionTitle}>
              Simple, declarative configuration
            </Heading>
            <p className={styles.sectionText}>
              Define your routes, upstreams, and plugins in a single YAML file.
              Hot reload without dropping connections.
            </p>
            <ul className={styles.featureList}>
              <li>Radix tree routing with host and path matching</li>
              <li>Multiple load balancing algorithms</li>
              <li>Per-route plugin configuration</li>
              <li>Health checks and circuit breakers</li>
              <li>Live configuration reload</li>
            </ul>
            <Link
              className="button button--primary"
              to="/docs/reference/configuration">
              Configuration Reference
            </Link>
          </div>
          <div className="col col--7">
            <CodeBlock language="yaml" title="loom.yaml">
              {configExample}
            </CodeBlock>
          </div>
        </div>
      </div>
    </section>
  );
}

function ArchitectureSection() {
  return (
    <section className={styles.section}>
      <div className="container">
        <div className={styles.sectionHeader}>
          <Heading as="h2" className={styles.sectionTitle}>
            Built for performance
          </Heading>
          <p className={styles.sectionSubtitle}>
            Sub-2ms plugin latency with AOT compilation. Process millions of requests with minimal overhead.
          </p>
        </div>
        <div className={styles.statsGrid}>
          <div className={styles.statCard}>
            <div className={styles.statNumber}>&lt;2ms</div>
            <div className={styles.statLabel}>Plugin latency</div>
          </div>
          <div className={styles.statCard}>
            <div className={styles.statNumber}>6</div>
            <div className={styles.statLabel}>Protocols supported</div>
          </div>
          <div className={styles.statCard}>
            <div className={styles.statNumber}>5</div>
            <div className={styles.statLabel}>Load balancing algorithms</div>
          </div>
          <div className={styles.statCard}>
            <div className={styles.statNumber}>0</div>
            <div className={styles.statLabel}>External dependencies</div>
          </div>
        </div>
      </div>
    </section>
  );
}

function ComparisonSection() {
  return (
    <section className={clsx(styles.section, styles.sectionAlt)}>
      <div className="container">
        <div className={styles.sectionHeader}>
          <Heading as="h2" className={styles.sectionTitle}>
            Why Loom?
          </Heading>
          <p className={styles.sectionSubtitle}>
            Modern features without the operational complexity.
          </p>
        </div>
        <div className={styles.comparisonTable}>
          <table>
            <thead>
              <tr>
                <th>Feature</th>
                <th>Loom</th>
                <th>Envoy</th>
                <th>Kong</th>
                <th>NGINX</th>
              </tr>
            </thead>
            <tbody>
              <tr>
                <td>WASM Plugins</td>
                <td className={styles.check}>Native</td>
                <td className={styles.check}>Yes</td>
                <td className={styles.partial}>Limited</td>
                <td className={styles.cross}>No</td>
              </tr>
              <tr>
                <td>Proxy-Wasm ABI</td>
                <td className={styles.check}>Full</td>
                <td className={styles.check}>Full</td>
                <td className={styles.cross}>No</td>
                <td className={styles.cross}>No</td>
              </tr>
              <tr>
                <td>HTTP/3 (QUIC)</td>
                <td className={styles.check}>Yes</td>
                <td className={styles.check}>Yes</td>
                <td className={styles.cross}>No</td>
                <td className={styles.check}>Yes</td>
              </tr>
              <tr>
                <td>AI/LLM Gateway</td>
                <td className={styles.check}>Built-in</td>
                <td className={styles.cross}>No</td>
                <td className={styles.partial}>Plugin</td>
                <td className={styles.cross}>No</td>
              </tr>
              <tr>
                <td>GraphQL Gateway</td>
                <td className={styles.check}>Built-in</td>
                <td className={styles.cross}>No</td>
                <td className={styles.partial}>Plugin</td>
                <td className={styles.cross}>No</td>
              </tr>
              <tr>
                <td>Zero Dependencies</td>
                <td className={styles.check}>Yes</td>
                <td className={styles.cross}>No</td>
                <td className={styles.cross}>No</td>
                <td className={styles.cross}>No</td>
              </tr>
              <tr>
                <td>Hot Reload</td>
                <td className={styles.check}>Yes</td>
                <td className={styles.check}>Yes</td>
                <td className={styles.check}>Yes</td>
                <td className={styles.partial}>Limited</td>
              </tr>
              <tr>
                <td>eBPF Acceleration</td>
                <td className={styles.check}>Yes</td>
                <td className={styles.partial}>Cilium</td>
                <td className={styles.cross}>No</td>
                <td className={styles.cross}>No</td>
              </tr>
            </tbody>
          </table>
        </div>
        <div className={styles.comparisonCta}>
          <Link
            className="button button--secondary"
            to="/docs/getting-started/why-loom">
            See detailed comparison
          </Link>
        </div>
      </div>
    </section>
  );
}

function CTASection() {
  return (
    <section className={styles.ctaSection}>
      <div className="container">
        <Heading as="h2" className={styles.ctaTitle}>
          Ready to get started?
        </Heading>
        <p className={styles.ctaSubtitle}>
          Deploy Loom in minutes with our quickstart guide.
        </p>
        <div className={styles.ctaButtons}>
          <Link
            className="button button--primary button--lg"
            to="/docs/getting-started/quickstart">
            Quickstart Guide
          </Link>
          <Link
            className="button button--secondary button--lg"
            to="/docs/getting-started/introduction">
            Read the Docs
          </Link>
        </div>
      </div>
    </section>
  );
}

export default function Home(): ReactNode {
  const {siteConfig} = useDocusaurusContext();
  return (
    <Layout
      title="WASM-First API Gateway"
      description="High-performance API Gateway with native WebAssembly plugin support. Route, transform, and secure your APIs with sub-millisecond latency.">
      <HomepageHeader />
      <main>
        <FeaturesSection />
        <ConfigExample />
        <ArchitectureSection />
        <ComparisonSection />
        <CTASection />
      </main>
    </Layout>
  );
}
