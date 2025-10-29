# Vulnerability Report Viewer

> 🏆 Developed during the 2025 Security Innovation Hackathon

A modern React-based web application that revolutionizes the way development teams handle security vulnerability reports. Born from the challenges of managing multiple security scanning tools, this application provides a unified, intuitive interface for analyzing and prioritizing security vulnerabilities detected by Trivy, Grype, and other security scanners.

![Security Report Viewer](public/logo192.png)

## Why This Project Exists

In modern DevSecOps practices, development teams often struggle with:

-   Managing outputs from multiple security scanning tools
-   Prioritizing which vulnerabilities to address first
-   Understanding the impact of security findings
-   Maintaining security compliance efficiently
-   Communicating security status across teams

This project, conceived and built during an intensive hackathon, addresses these challenges by providing a centralized, user-friendly dashboard for security vulnerability management.

## Key Benefits

### For Development Teams

-   🎯 **Immediate Focus**: Quickly identify high-priority security issues
-   🔄 **Streamlined Workflow**: Stop context-switching between different security tool reports
-   📊 **Clear Metrics**: Understand security status at a glance
-   🛠️ **Quick Fixes**: Easy access to remediation information

### For Security Teams

-   🔍 **Comprehensive Overview**: All security findings in one place
-   📈 **Trend Analysis**: Track security improvements over time
-   🎚️ **Risk Management**: Better prioritization of security issues
-   📱 **Mobile Friendly**: Access reports on any device

### For Management

-   📊 **Status Dashboard**: Clear view of project security health
-   💼 **Compliance Ready**: Easy reporting for audit requirements
-   📈 **Progress Tracking**: Monitor security improvements
-   🎯 **Resource Planning**: Better allocation of security resources

## Features

-   🔍 **Unified View**: Combines vulnerability reports from multiple security scanning tools
-   🎨 **Modern UI**: Built with Material-UI for a clean, responsive interface
-   🏷️ **Smart Filtering**: Filter vulnerabilities by severity, type, and other criteria
-   📊 **Visual Indicators**: Color-coded severity levels and intuitive icons
-   🔄 **Multiple Sources**: Support for Trivy, Grype, and combined vulnerability reports
-   📱 **Responsive Design**: Works seamlessly on desktop and mobile devices

## Getting Started

In the project directory, you can run:

### `npm start`

Runs the app in the development mode.\
Open [http://localhost:3000](http://localhost:3000) to view it in your browser.

The page will reload when you make changes.\
You may also see any lint errors in the console.

### `npm test`

Launches the test runner in the interactive watch mode.\
See the section about [running tests](https://facebook.github.io/create-react-app/docs/running-tests) for more information.

### `npm run build`

Builds the app for production to the `build` folder.\
It correctly bundles React in production mode and optimizes the build for the best performance.

The build is minified and the filenames include the hashes.\
Your app is ready to be deployed!

See the section about [deployment](https://facebook.github.io/create-react-app/docs/deployment) for more information.

### `npm run eject`

**Note: this is a one-way operation. Once you `eject`, you can't go back!**

If you aren't satisfied with the build tool and configuration choices, you can `eject` at any time. This command will remove the single build dependency from your project.

Instead, it will copy all the configuration files and the transitive dependencies (webpack, Babel, ESLint, etc) right into your project so you have full control over them. All of the commands except `eject` will still work, but they will point to the copied scripts so you can tweak them. At this point you're on your own.

You don't have to ever use `eject`. The curated feature set is suitable for most deployments.

## Usage

After starting the application, you can:

1. **View Reports**: The main interface displays vulnerability reports in an easy-to-read format
2. **Filter Results**: Use the severity filter to focus on specific vulnerability levels
3. **Sort Data**: Sort vulnerabilities by different criteria including severity and package name
4. **Expand Details**: Click on any vulnerability to see detailed information
5. **Switch Sources**: Toggle between Trivy, Grype, and combined report views

## Sample Data & API Integration

### Included Sample Reports

The project comes with sample vulnerability reports in the `src` directory:

-   `trivy-report.json`: Sample output from Trivy scanner
-   `grype-report.json`: Sample output from Grype scanner
-   `combined-report.json`: Sample of combined vulnerability data

These files serve as examples of the expected data format and can be used for testing and development purposes.

### API Integration Options

The application supports multiple ways to integrate with security scanners:

1. **Static JSON Files** (current implementation)

    ```javascript
    import trivyData from './trivy-report.json';
    import grypeData from './grype-report.json';
    ```

2. **Mock API Implementation**

    ```javascript
    // mockApi.js
    export const fetchVulnerabilityData = async (scanner) => {
        try {
            // Simulate API delay
            await new Promise((resolve) => setTimeout(resolve, 1000));

            switch (scanner) {
                case 'trivy':
                    return import('./trivy-report.json');
                case 'grype':
                    return import('./grype-report.json');
                case 'combined':
                    return import('./combined-report.json');
                default:
                    throw new Error('Invalid scanner type');
            }
        } catch (error) {
            console.error('Error fetching vulnerability data:', error);
            throw error;
        }
    };
    ```

3. **Live API Integration**
    ```javascript
    const API_ENDPOINTS = {
        trivy: '/api/scanners/trivy',
        grype: '/api/scanners/grype',
        combined: '/api/scanners/combined',
    };
    ```

## Technical Implementation

### Security Tools Integration

The application currently supports:

-   **Trivy**:
    -   Container and filesystem scanning
    -   Comprehensive vulnerability database
    -   Format: Standard Trivy JSON output
-   **Grype**:
    -   Deep dependency scanning
    -   Language-specific vulnerability detection
    -   Format: Standard Grype JSON output
-   **Combined Reports**:
    -   Aggregated view of multiple scanners
    -   Custom format for unified representation
    -   Enhanced with additional metadata

### Advanced Features

1. **Smart Filtering System**

    - Multi-criteria filtering
    - Customizable severity thresholds
    - Package-specific filtering

2. **Data Visualization**

    - Severity distribution charts
    - Trend analysis graphs
    - Package dependency visualization

3. **Report Generation**

    - Export to multiple formats
    - Customizable report templates
    - Compliance-ready outputs

4. **Performance Optimization**
    - Efficient data handling
    - Lazy loading for large reports
    - Optimized search algorithms

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

-   Built with [React](https://reactjs.org/) and [Material-UI](https://mui.com/)
-   Security scanning tools:
    -   [Trivy](https://github.com/aquasecurity/trivy)
    -   [Grype](https://github.com/anchore/grype)

## Hackathon Journey

This project was developed during an intensive 48-hour Security Innovation Hackathon, where the challenge was to improve the security workflow for development teams. Key achievements include:

-   🏃‍♂️ **Rapid Development**: Built a fully functional prototype in 48 hours
-   🎯 **Problem-Focused**: Addressed real-world security workflow challenges
-   🤝 **User-Centric**: Designed based on developer feedback and needs
-   🏆 **Innovation**: Introduced novel approaches to security visualization
-   🔄 **Integration**: Successfully combined multiple security tools into a unified interface

### Future Roadmap

1. **Enhanced Integration**

    - Support for more security scanning tools
    - CI/CD pipeline integration
    - Custom scanner integration capability

2. **Advanced Analytics**

    - Machine learning-based vulnerability prioritization
    - Predictive security analysis
    - Custom reporting templates

3. **Team Collaboration**
    - Real-time collaboration features
    - Team-based vulnerability management
    - Integration with issue tracking systems

## Contact & Support

Created with ❤️ by Sathwik - [@sathwik22](https://github.com/sathwik22)

Project Link: [https://github.com/sathwik22/hackathon-semantic](https://github.com/sathwik22/hackathon-semantic)

### Get Involved

-   🌟 Star this repo if you find it helpful
-   🐛 Report bugs and suggest features
-   🤝 Contribute to make it better
-   📢 Share with others who might benefit
