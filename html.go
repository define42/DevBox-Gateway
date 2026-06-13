package main

const loginHTML = `<!doctype html>
<html lang="en" data-bs-theme="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>DevBoxGateway</title>
  <link rel="stylesheet" href="/static/vendor/bootstrap/5.3.2/bootstrap.min.css">
  <link rel="stylesheet" href="/static/vendor/bootstrap-icons/1.11.3/bootstrap-icons.min.css">
  <link rel="stylesheet" href="/static/theme.css">
</head>
<body class="bg-body-tertiary d-flex align-items-center justify-content-center min-vh-100 py-4">
  <main class="container">
    <div class="row justify-content-center">
      <div class="col-12 col-md-7 col-lg-5 col-xl-4">
        <div class="card shadow-sm">
          <div class="card-body p-4 p-sm-5">
            <div class="text-center mb-4">
              <div class="brand-badge mx-auto mb-3"><i class="bi bi-boxes" aria-hidden="true"></i></div>
              <h1 class="h4 mb-1">DevBoxGateway</h1>
              <p class="text-body-secondary mb-0">Sign in to continue</p>
            </div>
            {{ERROR}}
            <form method="post" action="/login" class="mt-2">
              <div class="mb-3">
                <label class="form-label" for="username">Username</label>
                <div class="input-group">
                  <span class="input-group-text"><i class="bi bi-person" aria-hidden="true"></i></span>
                  <input class="form-control" id="username" name="username" autocomplete="username" required>
                </div>
              </div>
              <div class="mb-4">
                <label class="form-label" for="password">Password</label>
                <div class="input-group">
                  <span class="input-group-text"><i class="bi bi-lock" aria-hidden="true"></i></span>
                  <input class="form-control" id="password" name="password" type="password" autocomplete="current-password" required>
                </div>
              </div>
              <button class="btn btn-primary w-100" type="submit"><i class="bi bi-box-arrow-in-right me-1" aria-hidden="true"></i>Continue</button>
            </form>
          </div>
        </div>
      </div>
    </div>
  </main>
</body>
</html>
`
