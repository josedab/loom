import {themes as prismThemes} from 'prism-react-renderer';
import type {Config} from '@docusaurus/types';
import type * as Preset from '@docusaurus/preset-classic';

const config: Config = {
  title: 'Loom',
  tagline: 'WASM-First API Gateway',
  favicon: 'img/favicon.ico',

  future: {
    v4: true,
  },

  url: 'https://loom.dev',
  baseUrl: '/',

  organizationName: 'josedab',
  projectName: 'loom',

  onBrokenLinks: 'throw',
  onBrokenMarkdownLinks: 'warn',

  i18n: {
    defaultLocale: 'en',
    locales: ['en'],
  },

  markdown: {
    mermaid: true,
  },

  themes: ['@docusaurus/theme-mermaid'],

  presets: [
    [
      'classic',
      {
        docs: {
          sidebarPath: './sidebars.ts',
          editUrl: 'https://github.com/josedab/loom/tree/main/website/',
          showLastUpdateTime: true,
        },
        blog: {
          showReadingTime: true,
          feedOptions: {
            type: ['rss', 'atom'],
            xslt: true,
          },
          editUrl: 'https://github.com/josedab/loom/tree/main/website/',
        },
        theme: {
          customCss: './src/css/custom.css',
        },
      } satisfies Preset.Options,
    ],
  ],

  plugins: [
    [
      require.resolve('@easyops-cn/docusaurus-search-local'),
      {
        hashed: true,
        language: ['en'],
        highlightSearchTermsOnTargetPage: true,
        explicitSearchResultPath: true,
      },
    ],
  ],

  themeConfig: {
    image: 'img/loom-social-card.svg',
    colorMode: {
      defaultMode: 'dark',
      disableSwitch: false,
      respectPrefersColorScheme: true,
    },
    announcementBar: {
      id: 'star_us',
      content:
        'If you like Loom, give us a <a target="_blank" rel="noopener noreferrer" href="https://github.com/josedab/loom">star on GitHub</a>!',
      backgroundColor: '#1a1a2e',
      textColor: '#fff',
      isCloseable: true,
    },
    navbar: {
      title: 'Loom',
      logo: {
        alt: 'Loom Logo',
        src: 'img/logo.svg',
      },
      items: [
        {
          type: 'docSidebar',
          sidebarId: 'docsSidebar',
          position: 'left',
          label: 'Docs',
        },
        {
          to: '/docs/ai-gateway/overview',
          label: 'AI Gateway',
          position: 'left',
        },
        {
          to: '/docs/graphql/overview',
          label: 'GraphQL',
          position: 'left',
        },
        {to: '/blog', label: 'Blog', position: 'left'},
        {
          href: 'https://github.com/josedab/loom',
          label: 'GitHub',
          position: 'right',
        },
      ],
    },
    footer: {
      style: 'dark',
      links: [
        {
          title: 'Documentation',
          items: [
            {
              label: 'Getting Started',
              to: '/docs/getting-started/introduction',
            },
            {
              label: 'Core Concepts',
              to: '/docs/core-concepts/architecture',
            },
            {
              label: 'Configuration',
              to: '/docs/reference/configuration',
            },
          ],
        },
        {
          title: 'Features',
          items: [
            {
              label: 'AI Gateway',
              to: '/docs/ai-gateway/overview',
            },
            {
              label: 'GraphQL',
              to: '/docs/graphql/overview',
            },
            {
              label: 'Kubernetes',
              to: '/docs/kubernetes/gateway-api',
            },
          ],
        },
        {
          title: 'Community',
          items: [
            {
              label: 'GitHub',
              href: 'https://github.com/josedab/loom',
            },
            {
              label: 'GitHub Discussions',
              href: 'https://github.com/josedab/loom/discussions',
            },
            {
              label: 'Contributing',
              to: '/docs/community/contributing',
            },
          ],
        },
        {
          title: 'More',
          items: [
            {
              label: 'Blog',
              to: '/blog',
            },
            {
              label: 'Releases',
              href: 'https://github.com/josedab/loom/releases',
            },
          ],
        },
      ],
      copyright: `Copyright © ${new Date().getFullYear()} Loom Project. Built with Docusaurus.`,
    },
    prism: {
      theme: prismThemes.github,
      darkTheme: prismThemes.dracula,
      additionalLanguages: ['bash', 'yaml', 'rust', 'go', 'typescript', 'json', 'toml'],
    },
  } satisfies Preset.ThemeConfig,
};

export default config;
