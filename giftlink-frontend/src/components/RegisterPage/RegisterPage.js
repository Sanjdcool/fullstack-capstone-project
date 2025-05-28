import React, { useState } from 'react';
import './RegisterPage.css';
import { urlConfig } from '../../config';            // Task 1
import { useAppContext } from '../../context/AuthContext';  // Task 2
import { useNavigate } from 'react-router-dom';      // Task 3

function RegisterPage() {
  const [firstName, setFirstName] = useState('');
  const [lastName, setLastName] = useState('');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showerr, setShowerr] = useState('');          // Task 4: State for error message
  const navigate = useNavigate();                        // Task 5: Navigation handler
  const { setIsLoggedIn } = useAppContext();            // Task 5: Global login state setter


//   const handleRegister = async () => {
//     console.log('Register invoked');
//     // TODO: Add actual registration logic here
//   };
  const handleRegister = async () => {
    try {
        const response = await fetch(`${urlConfig.backendUrl}/api/auth/register`, {
            method: 'POST',                         // Task 6: POST method
            headers: {
                'content-type': 'application/json' // Task 7: Headers with JSON content type
            },
            body: JSON.stringify({                  // Task 8: Body with user details
                firstName,
                lastName,
                email,
                password
            })
        });
        const json = await response.json();   // Task 1
        console.log('json data', json);
        console.log('er', json.error);
        if (json.authtoken) {
            // Store token and user info in session storage  (Task 2)
            sessionStorage.setItem('auth-token', json.authtoken);
            sessionStorage.setItem('name', firstName);
            sessionStorage.setItem('email', json.email);

            setIsLoggedIn(true);                // Task 3: Update login state
            navigate('/app');                  // Task 4: Redirect to main app
        }
        if (json.error) {
            setShowerr(json.error);             // Task 5: Show error message
        }
    } catch (e) {
        console.log("Error fetching details: " + e.message);
        setShowerr("Registration failed. Please try again."); // Optional: handle fetch error
    }
}



  return (
    <div className="container mt-5">
      <div className="row justify-content-center">
        <div className="col-md-6 col-lg-4">
          <div className="register-card p-4 border rounded">
            <h2 className="text-center mb-4 font-weight-bold">Register</h2>

            <div className="mb-3">
              <label htmlFor="firstName" className="form-label">First Name</label>
              <input
                id="firstName"
                type="text"
                className="form-control"
                placeholder="Enter your first name"
                value={firstName}
                onChange={(e) => setFirstName(e.target.value)}
              />
            </div>

            <div className="mb-3">
              <label htmlFor="lastName" className="form-label">Last Name</label>
              <input
                id="lastName"
                type="text"
                className="form-control"
                placeholder="Enter your last name"
                value={lastName}
                onChange={(e) => setLastName(e.target.value)}
              />
            </div>

            <div className="mb-3">
              <label htmlFor="email" className="form-label">Email</label>
              <input
                id="email"
                type="email"
                className="form-control"
                placeholder="Enter your email"
                value={email}
                onChange={(e) => setEmail(e.target.value)}
              />
            </div>
                
                <div className="text-danger">{showerr}</div> {/* Task 6: Display error message in UI */}  


            <div className="mb-4">
              <label htmlFor="password" className="form-label">Password</label>
              <input
                id="password"
                type="password"
                className="form-control"
                placeholder="Enter your password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
              />
            </div>

            <button className="btn btn-primary w-100 mb-3" onClick={handleRegister}>Register</button>

            <p className="mt-4 text-center">
              Already a member? <a href="/app/login" className="text-primary">Login</a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default RegisterPage;


// import React, { useState } from 'react';
// //Step 1 - Task 1
// import {urlConfig} from '../../config';

// //Step 1 - Task 2
// import { useAppContext } from '../../context/AuthContext';

// //Step 1 - Task 3
// import { useNavigate } from 'react-router-dom';

// import './RegisterPage.css';

// function RegisterPage() {
//     const [firstName, setFirstName] = useState('');
//     const [lastName, setLastName] = useState('');
//     const [email, setEmail] = useState('');
//     const [password, setPassword] = useState('');

//     //Step 1 - Task 4
//         const [showerr, setShowerr] = useState('');

//     //Step 1 - Task 5
//     const navigate = useNavigate();
//     const { setIsLoggedIn } = useAppContext();

//     const handleRegister = async () => {
//         const response = await fetch(`${urlConfig.backendUrl}/api/auth/register`, {
//             //Step 1 - Task 6
//             method: 'POST',
//             //Step 1 - Task 7
//             headers: {
//                 'content-type': 'application/json',
//             },
//             //Step 1 - Task 8
//             body: JSON.stringify({
//                 firstName: firstName,
//                 lastName: lastName,
//                 email: email,
//                 password: password
//             })
//         });

//         //Step 2 - Task 1
//         const json = await response.json();
//         console.log('json data', json);
//         console.log('er', json.error);

//         //Step 2 - Task 2
//         if (json.authtoken) {
//             sessionStorage.setItem('auth-token', json.authtoken);
//             sessionStorage.setItem('name', firstName);
//             sessionStorage.setItem('email', json.email);
//         //Step 2 - Task 3
//             setIsLoggedIn(true);
//         //Step 2 - Task 4
//             navigate('/app');
//         }
//         if (json.error) {
//         //Step 2 - Task 5
//             setShowerr(json.error);
//         }
//     }

//     return (
//         <div className="container mt-5">
//             <div className="row justify-content-center">
//                 <div className="col-md-6 col-lg-4">
//                     <div className="register-card p-4 border rounded">
//                         <h2 className="text-center mb-4 font-weight-bold">Register</h2>
//                         <div className="mb-3">
//                             <label htmlFor="firstName" className="form-label">FirstName</label>
//                             <input
//                                 id="firstName"
//                                 type="text"
//                                 className="form-control"
//                                 placeholder="Enter your firstName"
//                                 value={firstName}
//                                 onChange={(e) => setFirstName(e.target.value)}
//                             />
//                         </div>

//                         {/* last name */}

//                         <div className="mb-3">
//                             <label htmlFor="lastName" className="form-label">LastName</label>
//                             <input
//                                 id="lastName"
//                                 type="text"
//                                 className="form-control"
//                                 placeholder="Enter your lastName"
//                                 value={lastName}
//                                 onChange={(e) => setLastName(e.target.value)}
//                             />
//                         </div>

//                         {/* email  */}
//                         <div className="mb-3">
//                             <label htmlFor="email" className="form-label">Email</label>
//                             <input
//                                 id="email"
//                                 type="text"
//                                 className="form-control"
//                                 placeholder="Enter your email"
//                                 value={email}
//                                 onChange={(e) => setEmail(e.target.value)}
//                             />
//                         {/* Step 2 - Task 6*/}

//                                 <div className="text-danger">{showerr}</div>
//                         </div>

//                         <div className="mb-4">
//                             <label htmlFor="password" className="form-label">Password</label>
//                             <input
//                                 id="password"
//                                 type="password"
//                                 className="form-control"
//                                 placeholder="Enter your password"
//                                 value={password}
//                                 onChange={(e) => setPassword(e.target.value)}
//                             />
//                         </div>
//                         <button className="btn btn-primary w-100 mb-3" onClick={handleRegister}>Register</button>
//                         <p className="mt-4 text-center">
//                             Already a member? <a href="/app/login" className="text-primary">Login</a>
//                         </p>
//                     </div>
//                 </div>
//             </div>
//         </div>
//     );
// }

// export default RegisterPage;