- ACLs are lists that define who has access to which asset/resource and the level of access they are provisioned. 
- The settings themselves are called Access Control Entries or ACE for short. 

Two Types of ACLs:
1. Discretionary Access Control List (DACL) - Defines which security principles are granted or denied access to an object. DACLs are made up of ACEs that either allow or deny access. 
2. System Access Control Lists (SACL) - Allow Admins to log access attempts made to secured objects. 

**Example of DACL**
![[Pasted image 20251112191756.png]]

**Example of SACL**
![[Pasted image 20251112191807.png]] 

----------
### Access Control Entries
- ACE is the name or group that is allowed or denied access to a certain network resource. 

**Three Main Types of ACEs**

| **ACE**              | **Description**                                                                                                                                                            |
| -------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `Access denied ACE`  | Used within a DACL to show that a user or group is explicitly denied access to an object                                                                                   |
| `Access allowed ACE` | Used within a DACL to show that a user or group is explicitly granted access to an object                                                                                  |
| `System audit ACE`   | Used within a SACL to generate audit logs when a user or group attempts to access an object. It records whether access was granted or not and what type of access occurred |

An ACE is made up of these four components: 
1. The security identifier (SID) of the user/group that has access to the object 
2. A flag denoting the type of ACE
3. A set of flags that specify whether or not child containers/objects can inherit the given ACE entry from the primary or parent object
4. An access mask which is a 32-Bit value that defines the rights granted to an object

![[Pasted image 20251112192218.png]]

-----------
### Why Do We Care About ACEs?

- As a penetration tester, Access Control Entries are often looked over for many years, and that could lead to a lot of juicy information. 

We will be focusing on a few specific AD ACEs that can be used to gain further access into the network: 
- [ForceChangePassword](https://bloodhound.specterops.io/resources/edges/force-change-password#forcechangepassword) - gives us the right to reset a user's password without first knowing their password (should be used cautiously and typically best to consult our client before resetting passwords).
- [GenericWrite](https://bloodhound.specterops.io/resources/edges/generic-write#genericwrite) - gives us the right to write to any non-protected attribute on an object. If we have this access over a user, we could assign them an SPN and perform a Kerberoasting attack (which relies on the target account having a weak password set). Over a group means we could add ourselves or another security principal to a given group. Finally, if we have this access over a computer object, we could perform a resource-based constrained delegation attack which is outside the scope of this module.
- [AddSelf](https://bloodhound.specterops.io/resources/edges/add-self#addself) - shows security groups that a user can add themselves to.
- [GenericAll](https://bloodhound.specterops.io/resources/edges/generic-all#genericall) - this grants us full control over a target object. Again, depending on if this is granted over a user or group, we could modify group membership, force change a password, or perform a targeted Kerberoasting attack. If we have this access over a computer object and the [Local Administrator Password Solution (LAPS)](https://www.microsoft.com/en-us/download/details.aspx?id=46899) is in use in the environment, we can read the LAPS password and gain local admin access to the machine which may aid us in lateral movement or privilege escalation in the domain if we can obtain privileged controls or gain some sort of privileged access.

![[Pasted image 20251112192706.png]]

