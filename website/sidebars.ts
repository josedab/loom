import type {SidebarsConfig} from '@docusaurus/plugin-content-docs';

const sidebars: SidebarsConfig = {
  docsSidebar: [
    {
      type: 'category',
      label: 'Getting Started',
      collapsed: false,
      items: [
        'getting-started/why-loom',
        'getting-started/introduction',
        'getting-started/installation',
        'getting-started/quickstart',
        'getting-started/first-plugin',
      ],
    },
    {
      type: 'category',
      label: 'Core Concepts',
      items: [
        'core-concepts/architecture',
        'core-concepts/routing',
        'core-concepts/upstreams',
        'core-concepts/plugins',
      ],
    },
    {
      type: 'category',
      label: 'Guides',
      items: [
        'guides/http3-setup',
        'guides/grpc-proxying',
        'guides/authentication',
        'guides/rate-limiting',
        'guides/caching',
        'guides/canary-deployments',
        'guides/traffic-shadowing',
        'guides/circuit-breakers',
        'guides/observability',
        {
          type: 'category',
          label: 'Migration',
          items: [
            'guides/migration-overview',
            'guides/migration-nginx',
            'guides/migration-kong',
            'guides/migration-envoy',
          ],
        },
      ],
    },
    {
      type: 'category',
      label: 'AI Gateway',
      items: [
        'ai-gateway/overview',
        'ai-gateway/multi-provider',
        'ai-gateway/token-accounting',
        'ai-gateway/semantic-caching',
        'ai-gateway/security',
      ],
    },
    {
      type: 'category',
      label: 'GraphQL',
      items: [
        'graphql/overview',
        'graphql/federation',
        'graphql/subscriptions',
        'graphql/security',
        'graphql/persisted-queries',
      ],
    },
    {
      type: 'category',
      label: 'Kubernetes',
      items: [
        'kubernetes/gateway-api',
        'kubernetes/deployment',
        'kubernetes/service-discovery',
      ],
    },
    {
      type: 'category',
      label: 'Advanced',
      items: [
        'advanced/ebpf-acceleration',
        'advanced/policy-engine',
        'advanced/chaos-engineering',
        'advanced/multi-tenancy',
      ],
    },
    {
      type: 'category',
      label: 'Reference',
      items: [
        'reference/configuration',
        'reference/admin-api',
        'reference/metrics',
        'reference/cli',
        'reference/faq',
        'reference/troubleshooting',
        'reference/benchmarks',
      ],
    },
    {
      type: 'category',
      label: 'Community',
      items: [
        'community/contributing',
        'community/code-of-conduct',
        'community/security',
        'community/changelog',
      ],
    },
  ],
};

export default sidebars;
