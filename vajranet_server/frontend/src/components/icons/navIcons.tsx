// Single source of truth for the nav glyphs used by both the sidebar
// (components/layout/Sidebar.tsx) and each page's hero header. Keeping them
// here means the sidebar icon and its page's header icon can never drift —
// both import the same component instead of duplicating inline <svg> markup.
import type { SVGProps } from 'react';

export type NavIconProps = SVGProps<SVGSVGElement>;

const svgProps = (props: NavIconProps): NavIconProps => ({
  fill: 'none',
  stroke: 'currentColor',
  viewBox: '0 0 24 24',
  ...props,
});

export const DashboardIcon = (props: NavIconProps) => (
  <svg {...svgProps(props)}>
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6" />
  </svg>
);

export const DevicesIcon = (props: NavIconProps) => (
  <svg {...svgProps(props)}>
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.75 17L9 20l-1 1h8l-1-1-.75-3M3 13h18M5 17h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v10a2 2 0 002 2z" />
  </svg>
);

export const AlertsIcon = (props: NavIconProps) => (
  <svg {...svgProps(props)}>
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M15 17h5l-1.405-1.405A2.032 2.032 0 0018 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9" />
  </svg>
);

export const ComplianceIcon = (props: NavIconProps) => (
  <svg {...svgProps(props)}>
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

export const PolicyManagementIcon = (props: NavIconProps) => (
  <svg {...svgProps(props)}>
    <path
      strokeLinecap="round"
      strokeLinejoin="round"
      strokeWidth={2}
      d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"
    />
  </svg>
);

export const NetworkSecurityIcon = (props: NavIconProps) => (
  <svg {...svgProps(props)}>
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8.684 13.342C8.886 12.938 9 12.482 9 12c0-.482-.114-.938-.316-1.342m0 2.684a3 3 0 110-2.684m0 2.684l6.632 3.316m-6.632-6l6.632-3.316m0 0a3 3 0 105.367-2.684 3 3 0 00-5.367 2.684zm0 9.316a3 3 0 105.368 2.684 3 3 0 00-5.368-2.684z" />
  </svg>
);

export const PatchManagementIcon = (props: NavIconProps) => (
  <svg {...svgProps(props)}>
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707M12 8v4l2 2m4-6a6 6 0 11-12 0 6 6 0 0112 0z" />
  </svg>
);

export const DomainReputationIcon = (props: NavIconProps) => (
  <svg {...svgProps(props)}>
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M3.6 9h16.8M3.6 15h16.8M12 3a15 15 0 010 18M12 3a15 15 0 000 18" />
  </svg>
);

export const ThreatHuntingIcon = (props: NavIconProps) => (
  <svg {...svgProps(props)}>
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 17v-2m3 2v-4m3 4v-6m2 10H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
  </svg>
);

export const AiAssistantIcon = (props: NavIconProps) => (
  <svg {...svgProps(props)}>
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z" />
  </svg>
);

export const HelpIcon = (props: NavIconProps) => (
  <svg {...svgProps(props)}>
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
  </svg>
);

export const RuleEngineIcon = (props: NavIconProps) => (
  <svg {...svgProps(props)}>
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 9v2.25m0 3.75h.008v.008H12V15zm9-3c0 4.556-3.32 8.335-7.671 9.043a2.25 2.25 0 01-1.658 0C7.32 20.335 4 16.556 4 12V5.412c0-.51.31-.968.783-1.155l7.5-2.917a.75.75 0 01.534 0l7.5 2.917c.473.187.783.645.783 1.155V12z" />
  </svg>
);

export const FileIntegrityIcon = (props: NavIconProps) => (
  <svg {...svgProps(props)}>
    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
  </svg>
);
