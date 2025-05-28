import React, { useState, useEffect } from 'react';
// Step 1 - Task 1
import { urlConfig } from '../../config';
// Step 1 - Task 2
import { useAppContext } from '../../context/AuthContext';
// Step 1 - Task 3
import { useNavigate } from 'react-router-dom';
import './LoginPage.css';

function LoginPage() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  // Step 1 - Task 4
  const [incorrect, setIncorrect] = useState('');
  // Step 1 - Task 5
  const navigate = useNavigate();
  const bearerToken = sessionStorage.getItem('bearer-token');
  const { setIsLoggedIn } = useAppContext();

  // Step 1 - Task 6: Redirect if already logged in
  useEffect(() => {
    if (sessionStorage.getItem('auth-token')) {
      navigate('/app');
    }
  }, [navigate]);

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      // Step 1 - Task 7,8,9: API call
      const res = await fetch(`${urlConfig.backendUrl}/api/auth/login`, {
        method: 'POST',
        headers: {
          'content-type': 'application/json',
          'Authorization': bearerToken ? `Bearer ${bearerToken}` : '',
        },
        body: JSON.stringify({
          email,
          password,
        }),
      });

      // Step 2 - Task 1: Parse response
      const json = await res.json();
      console.log('Json', json);

      if (json.authtoken) {
        // Step 2 - Task 2: Store user details
        sessionStorage.setItem('auth-token', json.authtoken);
        sessionStorage.setItem('name', json.userName);
        sessionStorage.setItem('email', json.userEmail);
        // Step 2 - Task 3: Set logged-in state
        setIsLoggedIn(true);
        // Step 2 - Task 4: Navigate to main page
        navigate('/app');
      } else {
        // Step 2 - Task 5: Clear inputs and set error message
        document.getElementById('email').value = '';
        document.getElementById('password').value = '';
        setIncorrect('Wrong password. Try again.');
        setTimeout(() => {
          setIncorrect('');
        }, 2000);
      }
    } catch (e) {
      console.error('Error fetching details:', e.message);
    }
  };

  return (
    <div className="container mt-5">
      <div className="row justify-content-center">
        <div className="col-md-6 col-lg-4">
          <div className="login-card p-4 border rounded">
            <h2 className="text-center mb-4 font-weight-bold">Login</h2>
            <form onSubmit={handleLogin}>
              <div className="mb-3">
                <label htmlFor="email" className="form-label">Email</label>
                <input
                  id="email"
                  type="text"
                  className="form-control"
                  placeholder="Enter your email"
                  value={email}
                  onChange={(e) => { setEmail(e.target.value); setIncorrect(''); }}
                  required
                />
              </div>
              <div className="mb-4">
                <label htmlFor="password" className="form-label">Password</label>
                <input
                  id="password"
                  type="password"
                  className="form-control"
                  placeholder="Enter your password"
                  value={password}
                  onChange={(e) => { setPassword(e.target.value); setIncorrect(''); }}
                  required
                />
                {/* Step 2 - Task 6: Display error message */}
                <span
                  style={{
                    color: 'red',
                    height: '.5cm',
                    display: 'block',
                    fontStyle: 'italic',
                    fontSize: '12px',
                  }}
                >
                  {incorrect}
                </span>
              </div>
              <button type="submit" className="btn btn-primary w-100 mb-3">Login</button>
            </form>
            <p className="mt-4 text-center">
              New here? <a href="/app/register" className="text-primary">Register Here</a>
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}

export default LoginPage;




// import React, { useState } from 'react';
// import './LoginPage.css';

// function LoginPage() {
//   const [email, setEmail] = useState('');
//   const [password, setPassword] = useState('');

//   const handleLogin = async (e) => {
//     e.preventDefault();
//     console.log('Login invoked');
//     // TODO: Add actual login logic here
//   };

//   return (
//     <div className="container mt-5">
//       <div className="row justify-content-center">
//         <div className="col-md-6 col-lg-4">
//           <div className="login-card p-4 border rounded">
//             <h2 className="text-center mb-4 font-weight-bold">Login</h2>

//             <div className="mb-3">
//               <label htmlFor="email" className="form-label">Email</label>
//               <input
//                 id="email"
//                 type="email"
//                 className="form-control"
//                 placeholder="Enter your email"
//                 value={email}
//                 onChange={(e) => setEmail(e.target.value)}
//               />
//             </div>

//             <div className="mb-4">
//               <label htmlFor="password" className="form-label">Password</label>
//               <input
//                 id="password"
//                 type="password"
//                 className="form-control"
//                 placeholder="Enter your password"
//                 value={password}
//                 onChange={(e) => setPassword(e.target.value)}
//               />
//             </div>

//             <button className="btn btn-primary w-100 mb-3" onClick={handleLogin}>Login</button>

//             <p className="mt-4 text-center">
//               New here? <a href="/app/register" className="text-primary">Register Here</a>
//             </p>
//           </div>
//         </div>
//       </div>
//     </div>
//   );
// }

// export default LoginPage;
