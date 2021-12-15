function Login(props) {
  return (
    <form method="POST" action="/login">
      <label>Username: <input type="text" name="username" /></label>
      <label>Password: <input type="password" name="password" /></label>
      <input type="submit" />
    </form>
  )
}

export default Login