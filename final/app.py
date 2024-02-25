from flask import Flask, render_template, request
from vulnerability_scanner import VulnerabilityScanner
import vulnerability_scanner
app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    target_url = request.form['url']
    scanner = VulnerabilityScanner(target_url)
    
    # Perform vulnerability tests
    tech_stack = scanner.find_tech_stack(target_url)
    wayback_url = vulnerability_scanner.get_wayback_url(target_url)
    injection_vulnerability = scanner.check_injection()
    auth_vulnerability = scanner.check_auth_vulnerability()
    sensitive_data_exposure = scanner.is_sensitive_data_exposure_vulnerable()
    xxe_vulnerability = scanner.check_xxe_vulnerability()
    broken_excess_control = scanner.check_broken_excess_control()
    security_misconfiguration = scanner.check_security_misconfiguration()
    xss_vulnerability = scanner.check_cross_site_scripting()
    insecure_deserialization = scanner.check_insecure_deserialization()
    insufficient_logging_monitoring = scanner.check_insufficient_logging_and_monitoring()
    
    return render_template('result.html', 
                           tech_stack=tech_stack, 
                           wayback_url=wayback_url,
                           injection_vulnerability=injection_vulnerability,
                           auth_vulnerability=auth_vulnerability,
                           sensitive_data_exposure=sensitive_data_exposure,
                           xxe_vulnerability=xxe_vulnerability,
                           broken_excess_control=broken_excess_control,
                           security_misconfiguration=security_misconfiguration,
                           xss_vulnerability=xss_vulnerability,
                           insecure_deserialization=insecure_deserialization,
                           insufficient_logging_monitoring=insufficient_logging_monitoring)

if __name__ == '__main__':
    app.run(debug=True)
