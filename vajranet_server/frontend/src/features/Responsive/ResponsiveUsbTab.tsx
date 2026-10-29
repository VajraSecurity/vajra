import ResponsiveHardwareBulkTab from './ResponsiveHardwareBulkTab';
import { buildUsbCommands } from './responsiveHardwareCommands';

const ResponsiveUsbTab = () => (
  <ResponsiveHardwareBulkTab
    variant="usb"
    panelId="responsive-panel-usb"
    ariaLabelledBy="responsive-tab-usb"
    buildCommands={buildUsbCommands}
  />
);

export default ResponsiveUsbTab;
