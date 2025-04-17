# Chris Garey #2417512
# This is original work by me, there are no other collaborators.
# Pseudocode
# Begin Prog
# Prompt user for height in inches
# Prompt user to input their weight in lbs
# Convert height from inches to meters using formula m = in x 0.0254
# Convert weight from lbs to kilograms using formula kg = lbs / 2.2046
# Calculate body mass index with formula (weight / height**2)
# Return results of body mass index to user
# End Prog

# Prompt user to input height and weight
height = input('What is your height? ')
weight = input('What is your weight? ')

# Convert height from inches to meters
height_conv = float(height) * 0.0254

# Convert weight from lbs to kgs
weight_conv = float(weight) / 2.2046

# Calculate BMI
bmi = float(weight_conv / height_conv**2)
bmi = int(bmi)
# Return results to user
print('Your BMI is: ' + str(bmi))