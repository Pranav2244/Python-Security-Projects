from flask import Flask, render_template, request

app = Flask(__name__)

def calculate_risk(impact, likelihood, formula, vulnerability=None, business_impact=None, control_effectiveness=None):
    if formula == 'multiply':
        return impact * likelihood
    elif formula == 'average':
        return (impact + likelihood) / 2
    elif formula == 'custom':
        if vulnerability is not None and business_impact is not None and control_effectiveness is not None:
            return (impact * likelihood * vulnerability * business_impact) / control_effectiveness
        else:
            return "Invalid input for custom formula"
    else:
        return "Invalid formula selected"

@app.route('/', methods=['GET', 'POST'])
def index():
    risk_score = None
    error = None
    if request.method == 'POST':
        try:
            impact = int(request.form['impact'])
            likelihood = int(request.form['likelihood'])
            vulnerability = int(request.form['vulnerability'])
            business_impact = int(request.form['business_impact'])
            formula = request.form['formula']
            
            # Default value for control effectiveness, could be set dynamically
            control_effectiveness = 5  # Assuming control effectiveness is a constant for now

            risk_score = calculate_risk(impact, likelihood, formula, vulnerability, business_impact, control_effectiveness)
        except KeyError as e:
            error = f"Missing form field: {e.args[0]}"
        except ValueError:
            error = "Invalid input: please enter valid numbers for all fields."
        
    return render_template('index.html', risk_score=risk_score, error=error)

if __name__ == '__main__':
    app.run(debug=True)